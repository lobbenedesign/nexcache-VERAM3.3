/* NexCache — Prototipo isolato: il kvstore scala con letture multi-thread?
 * ============================================================
 * Fase 1 del piano "motore multi-thread reale" (vedi
 * .claude/plans/bright-giggling-starfish.md nella history della sessione).
 *
 * Domanda a cui questo test deve rispondere, con numeri: se M thread
 * lettori, ciascuno fisso su un sottoinsieme disgiunto di shard del
 * kvstore, martellano kvstoreHashtableFindAndCopy() (la nuova variante
 * "copia mentre il lock e' tenuto", sicura per l'uso cross-thread) mentre
 * un thread scrittore continua a fare add/delete su shard casuali, il
 * throughput aggregato SCALA con M, o c'e' un collo di bottiglia nascosto
 * (allocator globale, contesa di cache) che vanifica il guadagno?
 *
 * Deliberatamente NON tocca alcun file del path client/comandi: usa solo
 * kvstore.c cosi' com'e' oggi, piu' la funzione additiva
 * kvstoreHashtableFindAndCopy() appena aggiunta. Zero rischio per il
 * server live.
 *
 * Uso: ./test_shard_parallel_read [secondi_per_round]  (default 2s)
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/kvstore.h"

/* wangHash64() is defined in util.c, which pulls in sds/sha256/fpconv just
 * for this one mixing function -- reimplemented here (verbatim, same
 * algorithm as util.c) so this test can link against a minimal object set
 * without dragging in the rest of util.c. hashtable.c only needs SOME
 * symbol named wangHash64 to exist for its (unused-by-us) iterator cleanup
 * path; this test never calls hashtableNext()/CleanupIterator, but the
 * linker still needs the symbol resolved. */
uint64_t wangHash64(uint64_t hash) {
    hash = (~hash) + (hash << 21);
    hash = hash ^ (hash >> 24);
    hash = (hash + (hash << 3)) + (hash << 8);
    hash = hash ^ (hash >> 14);
    hash = (hash + (hash << 2)) + (hash << 4);
    hash = hash ^ (hash >> 28);
    hash = hash + (hash << 31);
    return hash;
}

#define NUM_SHARDS 176
#define KEYS_PER_SHARD_APPROX 200

/* ── Entry minimale, indipendente da robj/sds/server.c ──────────────── */
typedef struct {
    char key[32];
    char value[64];
} TestEntry;

static const void *testEntryGetKey(const void *entry) {
    return ((const TestEntry *)entry)->key;
}

static uint64_t testKeyHash(const void *key) {
    /* FNV-1a: non deve essere la stessa funzione usata altrove, deve solo
     * distribuire bene per questo test. */
    const unsigned char *p = key;
    uint64_t h = 1469598103934665603ULL;
    while (*p) {
        h ^= *p++;
        h *= 1099511628211ULL;
    }
    return h;
}

static int testKeyCompare(const void *key1, const void *key2) {
    return strcmp((const char *)key1, (const char *)key2);
}

static hashtableType testHashtableType = {
    .entryGetKey = testEntryGetKey,
    .hashFunction = testKeyHash,
    .keyCompare = testKeyCompare,
    /* MANDATORY for any hashtableType used with kvstore: kvstore.c's
     * createHashtableIfNeeded() unconditionally writes a kvstoreHashtableMetadata
     * header into the space right after the hashtable struct (metadata->kvs =
     * kvs), relying on hashtableCreate() having reserved that space via this
     * callback. Every real hashtableType in the server (kvstoreKeysHashtableType
     * etc.) sets it; omitting it here caused a real, reproducible ASan
     * heap-buffer-overflow (8 bytes past the hashtable allocation) during
     * development of this test -- confirmed as a bug in this test's setup,
     * not in kvstore.c/hashtable.c. */
    .getMetadataSize = kvstoreHashtableMetadataSize,
};

/* ── Popolamento iniziale ────────────────────────────────────────────── */
/* NOTE: quale shard "possiede" una chiave e' deciso qui, esplicitamente,
 * dal parametro didx passato a kvstoreHashtableAdd() -- kvstore non
 * ricalcola un proprio hash per validare il didx scelto dal chiamante (e'
 * la stessa convenzione del server reale: getKVStoreIndexForKey() in db.c
 * calcola il didx UNA VOLTA e lo riusa identico per insert/lookup/delete
 * sulla stessa chiave). Qui uso direttamente l'indice di shard "s" incluso
 * nel nome della chiave, sia per l'inserimento sia per la lettura in
 * reader_thread/writer_thread piu' sotto -- coerente per costruzione, senza
 * bisogno di ricalcolare un hash. */
static int g_total_keys = 0;

static void populate(kvstore *kvs) {
    for (int s = 0; s < NUM_SHARDS; s++) {
        for (int i = 0; i < KEYS_PER_SHARD_APPROX; i++) {
            TestEntry *e = malloc(sizeof(TestEntry));
            snprintf(e->key, sizeof(e->key), "shard%d:key%d", s, i);
            snprintf(e->value, sizeof(e->value), "value-for-%s", e->key);
            kvstoreHashtableAdd(kvs, s, e);
            g_total_keys++;
        }
    }
}

/* ── Thread lettore ──────────────────────────────────────────────────── */
typedef struct {
    kvstore *kvs;
    int shard_start, shard_end; /* range [start, end) di proprieta' */
    atomic_int *stop_flag;
    long long ops_done;
} ReaderArg;

static void copyValueCb(void *entry, void *ctx) {
    TestEntry *e = (TestEntry *)entry;
    char *dst = (char *)ctx;
    memcpy(dst, e->value, sizeof(e->value));
}

static void *reader_thread(void *arg) {
    ReaderArg *a = (ReaderArg *)arg;
    char keybuf[32];
    char valbuf[64];
    long long ops = 0;
    int shard_span = a->shard_end - a->shard_start;
    unsigned int seed = (unsigned int)(size_t)arg;
    while (!atomic_load(a->stop_flag)) {
        int s = a->shard_start + (rand_r(&seed) % shard_span);
        int k = rand_r(&seed) % KEYS_PER_SHARD_APPROX;
        snprintf(keybuf, sizeof(keybuf), "shard%d:key%d", s, k);
        bool found = kvstoreHashtableFindAndCopy(a->kvs, s, keybuf, copyValueCb, valbuf);
        if (!found) {
            fprintf(stderr, "BUG: chiave %s non trovata nel proprio shard\n", keybuf);
            exit(1);
        }
        ops++;
    }
    a->ops_done = ops;
    return NULL;
}

/* ── Thread scrittore (simula il thread principale che continua a
 * scrivere durante le letture concorrenti) ─────────────────────────── */
typedef struct {
    kvstore *kvs;
    atomic_int *stop_flag;
    long long ops_done;
} WriterArg;

static void *writer_thread(void *arg) {
    WriterArg *a = (WriterArg *)arg;
    char keybuf[32];
    long long ops = 0;
    unsigned int seed = 12345;
    while (!atomic_load(a->stop_flag)) {
        int s = rand_r(&seed) % NUM_SHARDS;
        int k = rand_r(&seed) % KEYS_PER_SHARD_APPROX;
        snprintf(keybuf, sizeof(keybuf), "shard%d:key%d", s, k);
        /* Sovrascrive il valore: find+delete+re-add (kvstore non ha un
         * "replace" diretto nell'API pubblica minimale che uso qui). */
        void **ref = kvstoreHashtableFindRef(a->kvs, s, keybuf);
        if (ref) {
            TestEntry *e = (TestEntry *)*ref;
            snprintf(e->value, sizeof(e->value), "updated-%lld", ops);
        }
        ops++;
    }
    a->ops_done = ops;
    return NULL;
}

/* ── Un round: M lettori (+ 1 scrittore, se with_writer) per SECONDS secondi ── */
static double run_round(kvstore *kvs, int M, int seconds, int with_writer) {
    atomic_int stop_flag = 0;
    pthread_t readers[64];
    ReaderArg rargs[64];
    pthread_t writer;
    WriterArg wa = {.kvs = kvs, .stop_flag = &stop_flag, .ops_done = 0};

    int shards_per_reader = NUM_SHARDS / M;
    for (int i = 0; i < M; i++) {
        rargs[i].kvs = kvs;
        rargs[i].shard_start = i * shards_per_reader;
        rargs[i].shard_end = (i == M - 1) ? NUM_SHARDS : (i + 1) * shards_per_reader;
        rargs[i].stop_flag = &stop_flag;
        rargs[i].ops_done = 0;
        pthread_create(&readers[i], NULL, reader_thread, &rargs[i]);
    }
    if (with_writer) pthread_create(&writer, NULL, writer_thread, &wa);

    sleep(seconds);
    atomic_store(&stop_flag, 1);

    long long total_ops = 0;
    for (int i = 0; i < M; i++) {
        pthread_join(readers[i], NULL);
        total_ops += rargs[i].ops_done;
    }
    if (with_writer) pthread_join(writer, NULL);

    return (double)total_ops / seconds;
}

static void run_series(kvstore *kvs, int seconds, int with_writer, int ms[], int n_ms) {
    printf("%-10s %-20s %-12s\n", "M lettori", "letture/sec (agg.)", "vs M=1");
    printf("---------------------------------------------\n");
    double baseline = 0;
    for (int i = 0; i < n_ms; i++) {
        int M = ms[i];
        double ops_per_sec = run_round(kvs, M, seconds, with_writer);
        if (M == 1) baseline = ops_per_sec;
        printf("%-10d %-20.0f %.2fx\n", M, ops_per_sec, ops_per_sec / baseline);
    }
}

int main(int argc, char **argv) {
    int seconds = (argc > 1) ? atoi(argv[1]) : 2;

    kvstore *kvs = kvstoreCreate(&testHashtableType, NUM_SHARDS, KVSTORE_ALLOCATE_HASHTABLES_ON_DEMAND);
    if (!kvs) {
        fprintf(stderr, "kvstoreCreate fallita\n");
        return 1;
    }
    populate(kvs);
    printf("Popolate %d chiavi su %d shard.\n\n", g_total_keys, NUM_SHARDS);

    int ms[] = {1, 2, 3, 4, 6, 8};
    int n_ms = sizeof(ms) / sizeof(ms[0]);

    printf("=== Solo lettori (nessuno scrittore concorrente) ===\n");
    run_series(kvs, seconds, 0, ms, n_ms);

    printf("\n=== Lettori + 1 scrittore concorrente ===\n");
    run_series(kvs, seconds, 1, ms, n_ms);

    printf("\nNessun crash, nessuna chiave mancante durante le letture concorrenti.\n");
    printf("PASS\n");
    return 0;
}
