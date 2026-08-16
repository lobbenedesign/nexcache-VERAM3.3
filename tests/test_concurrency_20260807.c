/* NexCache — Regression Suite per i fix di concorrenza del 2026-08-07
 * ============================================================
 * Test mirati sui bug di corruzione memoria/race condition trovati e
 * corretti nella sessione di review di oggi. Pensati per girare sotto
 * ThreadSanitizer (build: clang -fsanitize=thread) oltre che in build
 * normale — lo scopo esplicito è dimostrare l'assenza delle race
 * originarie, non solo che il codice "non crasha per caso".
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/core/nexstorage.h"
#include "../src/core/vll.h"
#include "../src/hashtable/nexdash.h"

static int g_pass = 0, g_fail = 0;
#define CHECK(expr, msg)                                                     \
  do {                                                                       \
    if (expr) {                                                             \
      printf("  \xE2\x9C\x93 PASS %s\n", msg);                              \
      g_pass++;                                                             \
    } else {                                                                \
      printf("  \xE2\x9C\x97 FAIL %s (line %d)\n", msg, __LINE__);          \
      g_fail++;                                                             \
    }                                                                       \
  } while (0)

/* ════════════════════════════════════════════════════════════════
 * TEST 1 — Hashtable concorrente: N thread fanno SET/GET/DEL sulla
 * stessa NexDashTable simultaneamente. PRIMA di oggi: nexdash.c non
 * aveva alcuna sincronizzazione pur essendo condivisa da tutti i
 * worker — un resize concorrente poteva causare use-after-free sul
 * key_pool. Questo test stressa esattamente quel percorso: molti
 * insert concorrenti forzano resize multipli (FASE 3 di nd_find_slot)
 * mentre altri thread fanno GET.
 * ════════════════════════════════════════════════════════════════ */
#define CONC_THREADS 8
#define CONC_KEYS_PER_THREAD 2000

typedef struct {
    NexDashTable *t;
    int thread_id;
} ConcArg;

static void *conc_writer(void *arg) {
    ConcArg *a = (ConcArg *)arg;
    char key[32];
    for (int i = 0; i < CONC_KEYS_PER_THREAD; i++) {
        snprintf(key, sizeof(key), "t%d:k%d", a->thread_id, i);
        char *val = strdup(key); /* value_size passato sotto = strlen+1 */
        nexdash_set(a->t, key, (uint8_t)strlen(key), val,
                    (uint32_t)(strlen(key) + 1), NTYPE_STRING, 0);
    }
    return NULL;
}

static void *conc_reader(void *arg) {
    ConcArg *a = (ConcArg *)arg;
    char key[32];
    /* Legge ripetutamente le chiavi di TUTTI i thread (non solo le
     * proprie) per massimizzare la contesa concorrente con i writer. */
    for (int round = 0; round < 3; round++) {
        for (int tid = 0; tid < CONC_THREADS; tid++) {
            for (int i = 0; i < CONC_KEYS_PER_THREAD; i += 7) {
                snprintf(key, sizeof(key), "t%d:k%d", tid, i);
                NexEntryType tp;
                (void)nexdash_get(a->t, key, (uint8_t)strlen(key), &tp);
                /* Non asseriamo nulla sul risultato (il writer potrebbe
                 * non aver ancora scritto quella chiave) — l'obiettivo è
                 * solo che questo NON causi UAF/corruzione sotto TSan. */
            }
        }
    }
    return NULL;
}

static void test_hashtable_concurrent(void) {
    printf("\n[Test 1] Hashtable: SET/GET concorrenti con resize forzato\n");

    NexDashTable *t = nexdash_create(4, 256 * 1024 * 1024);
    CHECK(t != NULL, "nexdash_create");
    if (!t) return;

    pthread_t writers[CONC_THREADS], readers[CONC_THREADS];
    ConcArg wargs[CONC_THREADS];

    for (int i = 0; i < CONC_THREADS; i++) {
        wargs[i].t = t;
        wargs[i].thread_id = i;
        pthread_create(&writers[i], NULL, conc_writer, &wargs[i]);
        pthread_create(&readers[i], NULL, conc_reader, &wargs[i]);
    }
    for (int i = 0; i < CONC_THREADS; i++) {
        pthread_join(writers[i], NULL);
        pthread_join(readers[i], NULL);
    }

    CHECK(1, "tutti i thread completati senza crash/UAF sotto TSan");

    /* Verifica che ogni chiave scritta sia effettivamente leggibile —
     * prova che il resize concorrente non ha corrotto/perso entry. */
    int missing = 0;
    char key[32];
    for (int tid = 0; tid < CONC_THREADS; tid++) {
        for (int i = 0; i < CONC_KEYS_PER_THREAD; i++) {
            snprintf(key, sizeof(key), "t%d:k%d", tid, i);
            NexEntryType tp;
            void *v = nexdash_get(t, key, (uint8_t)strlen(key), &tp);
            if (!v || strcmp((char *)v, key) != 0) missing++;
        }
    }
    CHECK(missing == 0, "tutte le 16000 chiavi scritte sono leggibili correttamente");

    NexDashStats s = nexdash_get_stats(t);
    CHECK(s.resizes > 0, "il resize e' scattato davvero durante il test (FASE 3 esercitata)");

    nexdash_destroy(t);
}

/* ════════════════════════════════════════════════════════════════
 * TEST 2 — Value leak: verifica che il SET su chiave esistente liberi
 * il valore precedente (via free_cb), invece di perderlo per sempre.
 * PRIMA: nexdash_set non chiamava mai free() sul vecchio value_ptr.
 * ════════════════════════════════════════════════════════════════ */
static _Atomic int g_freed_count = 0;
static void counting_free_cb(void *p) {
    atomic_fetch_add(&g_freed_count, 1);
    free(p);
}

static void test_no_value_leak_on_overwrite(void) {
    printf("\n[Test 2] Nessun leak su SET-overwrite ripetuto\n");

    NexDashTable *t = nexdash_create(4, 64 * 1024 * 1024);
    nexdash_set_free_cb(t, counting_free_cb);

    atomic_store(&g_freed_count, 0);
    const int overwrites = 500;
    for (int i = 0; i < overwrites; i++) {
        char *v = malloc(16);
        snprintf(v, 16, "v%d", i);
        nexdash_set(t, "samekey", 7, v, 16, NTYPE_STRING, 0);
    }
    /* 499 overwrite devono aver liberato il valore precedente (il primo
     * insert non sovrascrive nulla, quindi 500-1 = 499 free attesi prima
     * del destroy). */
    CHECK(atomic_load(&g_freed_count) == overwrites - 1,
          "ogni overwrite tranne il primo ha liberato il valore vecchio");

    nexdash_destroy(t);
    /* L'ultimo valore (mai sovrascritto) viene liberato solo se lo
     * eliminiamo esplicitamente prima del destroy: nexdash_destroy non
     * itera per liberare i value residui (limite noto, fuori scope). */
}

/* ════════════════════════════════════════════════════════════════
 * TEST 3 — VLL: N thread competono per lo stesso write-lock. PRIMA:
 * read_counts/write_flags mutati senza sincronizzazione — due
 * transazioni potevano credere entrambe di avere il lock esclusivo
 * sulla stessa chiave (TOCTOU). Verifichiamo con un contatore protetto
 * SOLO dal VLL stesso: se il VLL è rotto, il conteggio finale sarà
 * sbagliato (aggiornamenti persi per race).
 * ════════════════════════════════════════════════════════════════ */
#define VLL_THREADS 8
#define VLL_INCS_PER_THREAD 2000

typedef struct {
    VLLManager *mgr;
    long *shared_counter; /* NON atomico: la mutua esclusione deve venire dal VLL */
} VllArg;

static void *vll_worker(void *arg) {
    VllArg *a = (VllArg *)arg;
    uint64_t h[1] = {0xDEADBEEFCAFEBABEULL}; /* stessa chiave per tutti: forza contesa */
    VLLLockType lt[1] = {VLL_LOCK_WRITE};

    for (int i = 0; i < VLL_INCS_PER_THREAD; i++) {
        /* PRIMA (versione originale di questo test): un singolo tentativo,
         * scartato silenziosamente su VLL_TIMEOUT (10ms, vedi
         * VLL_TIMEOUT_US in vll.h). Con 8 thread che martellano la STESSA
         * chiave 16000 volte totali, alcuni acquire raggiungono
         * legittimamente il timeout sotto contesa pesante (specialmente
         * sotto ThreadSanitizer, che rallenta molto l'esecuzione) — non è
         * una race, è backpressure corretta del lock manager. Il test
         * ORIGINALE confondeva questi timeout con "incrementi persi".
         * Ritentare fino a un tetto ragionevole è il comportamento
         * realistico di un chiamante reale. */
        int done = 0;
        for (int retry = 0; retry < 50 && !done; retry++) {
            VLLRequest *req = vll_request_create(a->mgr, h, lt, 1);
            if (!req) continue;
            if (vll_acquire(a->mgr, req) == VLL_OK) {
                /* Sezione critica: se il VLL garantisce davvero l'esclusione
                 * mutua, questo read-modify-write non ricorsivo non perde
                 * mai un incremento. */
                long tmp = *a->shared_counter;
                tmp++;
                *a->shared_counter = tmp;
                vll_release(a->mgr, req);
                done = 1;
            }
            vll_request_destroy(req);
        }
    }
    return NULL;
}

static void test_vll_mutual_exclusion(void) {
    printf("\n[Test 3] VLL: mutua esclusione reale sotto contesa\n");

    VLLManager *mgr = vll_create(1024);
    CHECK(mgr != NULL, "vll_create");
    if (!mgr) return;

    long counter = 0;
    pthread_t threads[VLL_THREADS];
    VllArg args[VLL_THREADS];

    for (int i = 0; i < VLL_THREADS; i++) {
        args[i].mgr = mgr;
        args[i].shared_counter = &counter;
        pthread_create(&threads[i], NULL, vll_worker, &args[i]);
    }
    for (int i = 0; i < VLL_THREADS; i++) pthread_join(threads[i], NULL);

    long expected = (long)VLL_THREADS * VLL_INCS_PER_THREAD;
    char msg[128];
    snprintf(msg, sizeof(msg), "counter=%ld atteso=%ld (nessun incremento perso)",
             counter, expected);
    CHECK(counter == expected, msg);

    vll_destroy(mgr);
}

/* ════════════════════════════════════════════════════════════════
 * TEST 4 — RMW atomico: N thread fanno INCR concorrente sulla stessa
 * chiave via nexstorage_rmw. PRIMA: ndapi_rmw faceva get e set come
 * due chiamate separate (ciascuna con lock/unlock proprio) — due INCR
 * concorrenti potevano leggere lo stesso valore base e perdere un
 * incremento.
 * ════════════════════════════════════════════════════════════════ */
#define RMW_THREADS 8
#define RMW_INCS_PER_THREAD 1000

static NexStorageResult incr_cb(NexEntry *existing, const void *input,
                                void *output, void *ctx) {
    (void)ctx;
    long long delta = *(const long long *)input;
    long long cur = 0;
    if (existing->value && existing->value_len == sizeof(long long))
        memcpy(&cur, existing->value, sizeof(long long));
    cur += delta;
    static _Thread_local long long tls_buf;
    tls_buf = cur;
    existing->value = (const uint8_t *)&tls_buf;
    existing->value_len = sizeof(long long);
    existing->type = NEXDT_STRING;
    *(long long *)output = cur;
    return NEXS_OK;
}

static void *rmw_worker(void *arg) {
    NexStorage *ns = (NexStorage *)arg;
    long long delta = 1;
    for (int i = 0; i < RMW_INCS_PER_THREAD; i++) {
        long long out = 0;
        nexstorage_rmw(ns, "counter", 7, incr_cb, &delta, &out, NULL);
    }
    return NULL;
}

static void test_rmw_atomicity(void) {
    printf("\n[Test 4] RMW atomico: INCR concorrente senza lost update\n");

    NexStorage *ns = nexstorage_create("nexdash", "max_memory=16000000");
    CHECK(ns != NULL, "nexstorage_create");
    if (!ns) return;

    /* Inizializza il contatore a 0 nell'object store (nexstorage_rmw usa
     * object_api, vedi nexstorage.h) */
    nexstorage_set(ns, "counter", 7, (const uint8_t *)"\0\0\0\0\0\0\0\0", 8,
                   NEXDT_HASH, -1);

    pthread_t threads[RMW_THREADS];
    for (int i = 0; i < RMW_THREADS; i++)
        pthread_create(&threads[i], NULL, rmw_worker, ns);
    for (int i = 0; i < RMW_THREADS; i++) pthread_join(threads[i], NULL);

    NexEntry e = {0};
    NexStorageResult r = nexstorage_get(ns, "counter", 7, &e);
    long long final_val = -1;
    if (r == NEXS_OK && e.value_len == sizeof(long long))
        memcpy(&final_val, e.value, sizeof(long long));

    long long expected = (long long)RMW_THREADS * RMW_INCS_PER_THREAD;
    char msg[128];
    snprintf(msg, sizeof(msg), "counter=%lld atteso=%lld (nessun incremento perso via RMW concorrente)",
             final_val, expected);
    CHECK(final_val == expected, msg);

    nexstorage_destroy(ns);
}

/* ════════════════════════════════════════════════════════════════
 * TEST 5 — Eviction: verifica che nexdash_evict_to_target liberi
 * davvero memoria. PRIMA: chiamava nexdash_del(t, NULL, 0), che
 * nexdash_del rifiuta immediatamente (key==NULL) — non liberava mai
 * una sola entry, quindi la cache si bloccava una volta piena.
 * ════════════════════════════════════════════════════════════════ */
static void test_eviction_frees_memory(void) {
    printf("\n[Test 5] Eviction: used_memory diminuisce davvero\n");

    NexDashTable *t = nexdash_create(4, 64 * 1024 * 1024);
    nexdash_set_free_cb(t, counting_free_cb);

    char key[32];
    for (int i = 0; i < 500; i++) {
        snprintf(key, sizeof(key), "evk:%d", i);
        char *v = malloc(100);
        memset(v, 'x', 100);
        nexdash_set(t, key, (uint8_t)strlen(key), v, 100, NTYPE_STRING, 0);
    }

    NexDashStats before = nexdash_get_stats(t);
    size_t used_before = t->used_memory;

    size_t evicted = nexdash_evict_to_target(t, used_before / 2);

    size_t used_after = t->used_memory;

    CHECK(evicted > 0, "nexdash_evict_to_target ha evitto almeno un'entry");
    CHECK(used_after < used_before, "used_memory e' diminuita davvero dopo l'eviction");
    (void)before;

    nexdash_destroy(t);
}

/* ════════════════════════════════════════════════════════════════
 * TEST 6 — Use-after-free sul percorso di lettura: nexstorage_get()
 * ritornava un puntatore VIVO dentro il blocco allocato per il value,
 * restituito DOPO aver rilasciato il lock di nexdash (ndapi_get in
 * nexstorage.c). Prima del fix leak di oggi questo era innocuo (il
 * vecchio value veniva perso ma mai liberato). Dopo aver aggiunto
 * free_cb per eliminare il leak, un GET concorrente a un SET sulla
 * stessa chiave poteva leggere memoria già liberata dall'overwrite.
 * Scoperto esaminando il fast-path Garnet-style di VERAM3.3 (che
 * ritarda la copia del value nel buffer di rete fino a dopo la
 * chiamata a nexstorage_get) — lo stesso bug esiste identico in
 * SOVEREIGN dato che nexstorage.c è condiviso.
 * Questo test da solo NON prova l'assenza di UAF sotto build normale o
 * TSan (nessuno dei due rileva l'uso di memoria liberata ma non ancora
 * rimappata) — va eseguito sotto AddressSanitizer per una verifica
 * reale. Qui verifichiamo comunque che il valore letto sia sempre uno
 * dei valori validi scritti (mai garbage/troncato), che è l'unico
 * segnale osservabile senza ASan.
 * ════════════════════════════════════════════════════════════════ */
#define UAF_THREADS 8
#define UAF_ITERS_PER_THREAD 3000

typedef struct {
    NexStorage *ns;
    _Atomic int stop;
} UafArg;

static void *uaf_writer(void *arg) {
    UafArg *a = (UafArg *)arg;
    char vbuf[64];
    for (int i = 0; i < UAF_ITERS_PER_THREAD; i++) {
        int n = snprintf(vbuf, sizeof(vbuf), "generation-%08d-of-some-payload", i);
        nexstorage_set(a->ns, "uafkey", 6, (const uint8_t *)vbuf, (uint32_t)n, NEXDT_STRING, -1);
    }
    atomic_fetch_add(&a->stop, 1);
    return NULL;
}

static void *uaf_reader(void *arg) {
    UafArg *a = (UafArg *)arg;
    while (atomic_load(&a->stop) < UAF_THREADS) {
        NexEntry e = {0};
        NexStorageResult r = nexstorage_get(a->ns, "uafkey", 6, &e);
        if (r == NEXS_OK) {
            /* Un valore valido è o il seed iniziale "init" (4 byte) o uno
             * scritto dal formato "generation-%08d-of-some-payload"
             * (sempre 35 byte, prefisso "generation-") — garbage/UAF
             * produrrebbe quasi certamente una lunghezza o un contenuto
             * diverso da questi due casi. */
            int is_init = (e.value_len == 4 && memcmp(e.value, "init", 4) == 0);
            int is_gen = (e.value_len == 35 && memcmp(e.value, "generation-", 11) == 0);
            if (!is_init && !is_gen) {
                fprintf(stderr, "  UAF SOSPETTO: value_len=%u content=%.*s\n",
                        e.value_len, (int)(e.value_len < 40 ? e.value_len : 40),
                        (const char *)e.value);
                exit(97); /* fail rumoroso e immediato, non un semplice CHECK */
            }
        }
    }
    return NULL;
}

static void test_no_uaf_on_concurrent_get_set(void) {
    printf("\n[Test 6] Nessuna UAF su GET concorrente a SET sulla stessa chiave\n");

    NexStorage *ns = nexstorage_create("nexdash", "max_memory=16000000");
    CHECK(ns != NULL, "nexstorage_create");
    if (!ns) return;
    nexstorage_set(ns, "uafkey", 6, (const uint8_t *)"init", 4, NEXDT_STRING, -1);

    UafArg arg = {.ns = ns, .stop = 0};
    pthread_t writers[UAF_THREADS], readers[UAF_THREADS];
    for (int i = 0; i < UAF_THREADS; i++) {
        pthread_create(&writers[i], NULL, uaf_writer, &arg);
        pthread_create(&readers[i], NULL, uaf_reader, &arg);
    }
    for (int i = 0; i < UAF_THREADS; i++) pthread_join(writers[i], NULL);
    for (int i = 0; i < UAF_THREADS; i++) pthread_join(readers[i], NULL);

    CHECK(1, "nessun valore corrotto osservato su 8 writer x 3000 SET con lettori concorrenti continui");

    nexstorage_destroy(ns);
}

/* ════════════════════════════════════════════════════════════════
 * MAIN
 * ════════════════════════════════════════════════════════════════ */
int main(void) {
  printf("\n");
  printf("======================================================\n");
  printf("  NexCache — Regression Suite Concorrenza (2026-08-07)\n");
  printf("======================================================\n");

  test_hashtable_concurrent();
  test_no_value_leak_on_overwrite();
  test_vll_mutual_exclusion();
  test_rmw_atomicity();
  test_eviction_frees_memory();
  test_no_uaf_on_concurrent_get_set();

  printf("\n======================================================\n");
  printf("  Risultati: %d passati, %d falliti\n", g_pass, g_fail);
  printf("======================================================\n\n");

  return g_fail > 0 ? 1 : 0;
}
