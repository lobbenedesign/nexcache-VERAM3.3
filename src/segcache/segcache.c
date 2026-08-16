/* NexSegcache — Implementazione
 * Ispirato a Segcache di CMU (NSDI'21 Best Paper Award).
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "segcache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint32_t seg_unix_now(void) {
    return (uint32_t)time(NULL);
}

static void *segcache_reaper_thread(void *arg) {
    NexSegcache *sc = (NexSegcache *)arg;
    while (sc->running) {
        sleep(1);
        if (!sc->running) break;
        segcache_expire_segments(sc);
    }
    return NULL;
}

/* ── FNV-1a 64 bit per hash table ───────────────────────────── */
static uint64_t seg_hash(const char *key, uint16_t key_len) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (uint16_t i = 0; i < key_len; i++)
        h = (h ^ (uint8_t)key[i]) * 0x100000001b3ULL;
    return h;
}

/* TTL → bucket index: raggruppa TTL simili nello stesso bucket
 * Granularità progressiva: 1s per TTL<60s, 10s per TTL<600s, ecc. */
static uint32_t ttl_to_bucket(uint32_t ttl_seconds) {
    if (ttl_seconds == 0) return 0;
    if (ttl_seconds < 60) return ttl_seconds;
    if (ttl_seconds < 600) return 60 + (ttl_seconds - 60) / 10;
    if (ttl_seconds < 3600) return 60 + 54 + (ttl_seconds - 600) / 60;
    return (60 + 54 + 50 + (ttl_seconds - 3600) / 3600) % SEG_TTL_BUCKETS;
}

/* Inversa di ttl_to_bucket: dato un bucket, ricostruisce il TTL (in
 * secondi) rappresentativo. PRIMA questa logica era duplicata tre volte
 * (ht_find, segcache_exists, segcache_expire_segments) e in tutti e tre i
 * punti usava solo 3 rami invece dei 4 del forward — per bucket>=164
 * (cioè qualunque TTL originale >=3600s) applicava il fattore *60 del
 * terzo ramo invece di *3600, ricostruendo un TTL molto più corto
 * dell'originale (es. TTL=7200s → bucket 165 → ricostruito come 3660s):
 * qualunque entry con TTL >=~1h scadeva con ~1h+ di anticipo.
 * Nota: per bucket>=164 l'informazione oltre l'ora è comunque quantizzata
 * a passi di 3600s (design del bucketing, non un bug), e per TTL
 * abbastanza grandi da avvolgere SEG_TTL_BUCKETS il forward stesso fa
 * aliasing via modulo — limite noto della granularità, non ricostruibile
 * senza cambiare cosa viene persistito per segmento. */
static uint32_t bucket_to_ttl_seconds(uint32_t b) {
    if (b == 0) return 0;
    if (b < 60) return b;
    if (b < 114) return 60 + (b - 60) * 10;
    if (b < 164) return 600 + (b - 114) * 60;
    return 3600 + (b - 164) * 3600;
}

/* ── segcache_create ─────────────────────────────────────────── */
NexSegcache *segcache_create(size_t max_memory, uint32_t segment_size) {
    if (segment_size == 0) segment_size = SEG_DEFAULT_SIZE;

    NexSegcache *sc = (NexSegcache *)calloc(1, sizeof(NexSegcache));
    if (!sc) return NULL;

    sc->max_memory = max_memory;
    sc->n_segments = (uint32_t)(max_memory / segment_size);
    if (sc->n_segments == 0) sc->n_segments = 16;
    /* NEX-FIX: il pool di segmenti è globale ma ogni shard TTL ha bisogno
     * di poter tenere almeno un segmento vivo contemporaneamente. Con meno
     * segmenti totali di NEX_RCU_SHARDS, non appena più shard di quanti
     * segmenti disponibili ricevono la loro prima scrittura, seg_alloc()
     * esaurisce il pool e segcache_set() fallisce silenziosamente per
     * tutti gli shard "in eccesso" — anche con una cache quasi vuota.
     * Riprodotto con max_memory=16MB/segment_size=256KB (64 segmenti) su
     * NEX_RCU_SHARDS=176: 1000 set falliscono appena >64 shard distinti
     * vengono toccati. Garantiamo un pavimento pari al numero di shard. */
    if (sc->n_segments < NEX_RCU_SHARDS) sc->n_segments = NEX_RCU_SHARDS;
    if (sc->n_segments > SEG_MAX_SEGMENTS) sc->n_segments = SEG_MAX_SEGMENTS;

    /* Pre-alloca tutti i segmenti con allineamento a 256-byte (SVI-Ready) */
    sc->segments = (NexSegment *)calloc(sc->n_segments, sizeof(NexSegment));
    if (!sc->segments) {
        free(sc);
        return NULL;
    }

    for (uint32_t i = 0; i < sc->n_segments; i++) {
        /* NEX-VERA: Allineamento a 256 byte per Small-Value Inlining (SVI) 
         * Questo assicura che ogni segmento inizi su una cache line pulita della CPU Olympus. */
        if (posix_memalign((void **)&sc->segments[i].data, 256, segment_size) != 0) {
            for (uint32_t j = 0; j < i; j++) free(sc->segments[j].data);
            free(sc->segments);
            free(sc);
            return NULL;
        }
        memset(sc->segments[i].data, 0, segment_size);
        sc->segments[i].data_size = segment_size;
    }

    /* NEX-VERA: Phase 3 - Lock-Free MPSC Pool 
     * Eliminates sc->pool_lock contention during segment allocation. */
    mpsc_init(&sc->free_queue);

    for (uint32_t i = 0; i < sc->n_segments; i++) {
        mpsc_node_t *node = (mpsc_node_t *)malloc(sizeof(mpsc_node_t));
        node->data = (void *)(uintptr_t)i;
        mpsc_enqueue(&sc->free_queue, node);
    }
    atomic_store(&sc->n_free, sc->n_segments);

    /* Inizializza TTL shards */
    for (int i = 0; i < NEX_RCU_SHARDS; i++) {
        sc->ttl_shards[i] = (NexSegment **)calloc(SEG_TTL_BUCKETS, sizeof(NexSegment *));
    }

    /* Hash table bulk-chaining (SHARDED) */
    sc->hash_table = (SegHashBucket *)calloc(SEG_HASH_BUCKETS, sizeof(SegHashBucket));
    sc->buckets_per_shard = SEG_BUCKETS_PER_SHARD;

    for (int i = 0; i < NEX_RCU_SHARDS; i++) {
        pthread_rwlock_init(&sc->locks[i], NULL);
    }
    sc->running = 1;

    if (pthread_create(&sc->reaper_thread, NULL, segcache_reaper_thread, sc) != 0) {
        fprintf(stderr, "[NexCache Segcache] WARNING: reaper thread non avviato — "
                        "i segmenti scaduti non verranno mai riciclati\n");
        sc->reaper_thread = 0;
    }

    fprintf(stderr,
            "[NexCache Segcache] G3-GODMODE Init: %d shards | %u segments @ %zuMB\n"
            "  Vera (Rubin) optimized RCU Shard Topology\n",
            NEX_RCU_SHARDS, sc->n_segments, max_memory / 1024 / 1024);
    return sc;
}

/* ── Preleva un segmento dal pool libero (LOCK-FREE MPSC) ─────── */
static NexSegment *seg_alloc(NexSegcache *sc, uint32_t ttl_bucket) {
    mpsc_node_t *node = mpsc_dequeue(&sc->free_queue);
    if (!node) return NULL;
    
    uint32_t idx = (uint32_t)(uintptr_t)node->data;
    free(node); // In a production system, use a node pool to avoid malloc in hot path
    
    atomic_fetch_sub(&sc->n_free, 1);
    NexSegment *seg = &sc->segments[idx];
    memset(seg->data, 0, seg->data_size);
    seg->write_offset = 0;
    seg->n_items = 0;
    seg->ttl_bucket = ttl_bucket;
    seg->create_time = seg_unix_now();
    seg->next = seg->prev = NULL;
    return seg;
}

/* ── Hash table: inserimento ─────────────────────────────────── */
/* NEX-FIX: replace-or-insert. The old version blindly appended, so an
 * overwrite of an existing key left BOTH versions in the bucket and lookups
 * returned the OLDEST one (stale reads on every SET-overwrite). We now scan
 * for an existing same-key entry first and update it in place. */
static int ht_insert(NexSegcache *sc, uint64_t hash, uint16_t key_fp, uint32_t seg_idx, uint32_t item_offset,
                     const char *key, uint16_t key_len) {
    int shard_id = (int)(hash % NEX_RCU_SHARDS);
    uint32_t local_idx = (uint32_t)((hash / NEX_RCU_SHARDS) % sc->buckets_per_shard);
    uint32_t global_idx = (uint32_t)(shard_id * sc->buckets_per_shard) + local_idx;
    SegHashBucket *bkt = &sc->hash_table[global_idx];

    int free_slot = -1;
    for (int s = 0; s < SEG_ITEMS_PER_BUCKET; s++) {
        if (!((bkt->occupancy >> s) & 1)) {
            if (free_slot < 0) free_slot = s;
            continue;
        }
        if (bkt->entries[s].key_fp != key_fp) continue;
        /* Possible existing version of the same key: verify the stored key. */
        NexSegment *seg = &sc->segments[bkt->entries[s].seg_idx];
        uint8_t *item_ptr = seg->data + bkt->entries[s].item_offset;
        SegItemHeader hdr;
        memcpy(&hdr, item_ptr, sizeof(hdr));
        if (SEG_HDR_KEY_LEN(hdr) == key_len &&
            memcmp((const char *)(item_ptr + sizeof(hdr)), key, key_len) == 0) {
            bkt->entries[s].seg_idx = (uint16_t)seg_idx;
            bkt->entries[s].item_offset = item_offset;
            return 0;
        }
    }
    if (free_slot >= 0) {
        bkt->entries[free_slot].key_fp = key_fp;
        bkt->entries[free_slot].seg_idx = (uint16_t)seg_idx;
        bkt->entries[free_slot].item_offset = item_offset;
        bkt->occupancy |= (1u << free_slot);
        return 0;
    }
    return -1; /* Bucket pieno */
}

/* ── Hash table: ricerca ─────────────────────────────────────── */
static SegHashEntry *ht_find(NexSegcache *sc, uint64_t hash, uint16_t key_fp, const char *key, uint16_t key_len) {
    int shard_id = (int)(hash % NEX_RCU_SHARDS);
    uint32_t local_idx = (uint32_t)((hash / NEX_RCU_SHARDS) % sc->buckets_per_shard);
    uint32_t global_idx = (uint32_t)(shard_id * sc->buckets_per_shard) + local_idx;
    SegHashBucket *bkt = &sc->hash_table[global_idx];

    for (int s = 0; s < SEG_ITEMS_PER_BUCKET; s++) {
        if (!((bkt->occupancy >> s) & 1)) continue;
        if (bkt->entries[s].key_fp != key_fp) continue;

        /* Verifica chiave nel segmento */
        NexSegment *seg = &sc->segments[bkt->entries[s].seg_idx];
        uint8_t *item_ptr = seg->data + bkt->entries[s].item_offset;
        SegItemHeader hdr;
        memcpy(&hdr, item_ptr, sizeof(hdr));

        if (SEG_HDR_KEY_LEN(hdr) == key_len) {
            const char *stored_key = (const char *)(item_ptr + sizeof(hdr));
            if (memcmp(stored_key, key, key_len) == 0) {
                /* Verifica TTL: calc expire time dal segmento */
                uint32_t ttl_s = bucket_to_ttl_seconds(seg->ttl_bucket);
                uint32_t expire = seg->create_time + ttl_s;
                if (ttl_s > 0 && expire <= seg_unix_now()) {
                    /* Scaduto: report as miss WITHOUT mutating the bucket —
                     * ht_find runs under a read lock (segcache_get), so it must
                     * not touch occupancy. Reclamation happens lazily on the
                     * next write to this key or via segcache_expire_segments. */
                    return NULL;
                }
                return &bkt->entries[s];
            }
        }
    }
    return NULL;
}

/* ── segcache_set ────────────────────────────────────────────── */
int segcache_set(NexSegcache *sc, const char *key, uint16_t key_len, const uint8_t *value, uint16_t value_len, uint32_t ttl_seconds) {
    if (!sc || !key || !value) return -1;

    uint32_t item_size = (uint32_t)(sizeof(SegItemHeader) + key_len + value_len);
    uint64_t hash64 = seg_hash(key, key_len);
    int shard_id = (int)(hash64 % NEX_RCU_SHARDS);
    SegStats *st = &sc->shard_stats[shard_id];

    pthread_rwlock_wrlock(&sc->locks[shard_id]);

    uint32_t ttl_b = ttl_to_bucket(ttl_seconds);

    /* Trova/crea segmento per questo TTL bucket nello shard */
    NexSegment *seg = sc->ttl_shards[shard_id][ttl_b];
    if (!seg || seg->write_offset + item_size > seg->data_size) {
        seg = seg_alloc(sc, ttl_b);
        if (!seg) {
            pthread_rwlock_unlock(&sc->locks[shard_id]);
            return -1; /* Out of segments */
        }
        seg->next = sc->ttl_shards[shard_id][ttl_b];
        if (sc->ttl_shards[shard_id][ttl_b])
            sc->ttl_shards[shard_id][ttl_b]->prev = seg;
        sc->ttl_shards[shard_id][ttl_b] = seg;
    }

    /* Calcola indice del segmento */
    uint32_t seg_idx = (uint32_t)(seg - sc->segments);
    uint32_t item_offset = seg->write_offset;

    /* Scrivi header + key + value nel buffer del segmento */
    uint16_t key_fp = (uint16_t)(hash64 >> 48);

    SegItemHeader hdr = 0;
    hdr |= ((uint64_t)key_fp << 48);
    hdr |= ((uint64_t)key_len << 32);
    hdr |= ((uint64_t)value_len << 16);
    hdr |= (uint64_t)ttl_b;

    uint8_t *dst = seg->data + seg->write_offset;
    memcpy(dst, &hdr, sizeof(hdr));
    memcpy(dst + sizeof(hdr), key, key_len);
    memcpy(dst + sizeof(hdr) + key_len, value, value_len);

    seg->write_offset += item_size;
    seg->n_items++;

    /* Inserisci in hash table.
     * NEX-FIX: propagate index-insert failure — the old code discarded the
     * return value, so a full bucket meant the item was written to the
     * segment but unreachable forever, while the caller was told "OK". */
    if (ht_insert(sc, hash64, key_fp, seg_idx, item_offset, key, key_len) != 0) {
        seg->write_offset -= item_size;
        seg->n_items--;
        pthread_rwlock_unlock(&sc->locks[shard_id]);
        return -1;
    }

    atomic_fetch_add(&sc->used_memory, item_size);
    st->sets++;
    st->bytes_stored += item_size;

    pthread_rwlock_unlock(&sc->locks[shard_id]);
    return 0;
}

/* ── segcache_get ────────────────────────────────────────────── */
int segcache_get(NexSegcache *sc, const char *key, uint16_t key_len, uint8_t *value_buf, uint16_t buf_len, uint16_t *value_len_out) {
    if (!sc || !key || !value_buf) return -1;

    uint64_t hash64 = seg_hash(key, key_len);
    uint16_t key_fp = (uint16_t)(hash64 >> 48);
    int shard_id = (int)(hash64 % NEX_RCU_SHARDS);
    SegStats *st = &sc->shard_stats[shard_id];

    /* Read lock: concurrent GETs on the same shard run in parallel. ht_find is
     * read-only (expired entries are reported as misses, not deleted here — the
     * writer paths and segcache_expire_segments reclaim them). Stats are updated
     * with atomic increments so concurrent readers don't corrupt the counters;
     * the per-op hit_rate division was removed (computed lazily in get_stats). */
    pthread_rwlock_rdlock(&sc->locks[shard_id]);
    SegHashEntry *entry = ht_find(sc, hash64, key_fp, key, key_len);
    if (!entry) {
        pthread_rwlock_unlock(&sc->locks[shard_id]);
        __atomic_fetch_add(&st->misses, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&st->gets, 1, __ATOMIC_RELAXED);
        return -1;
    }

    NexSegment *seg = &sc->segments[entry->seg_idx];
    uint8_t *item_ptr = seg->data + entry->item_offset;
    SegItemHeader hdr;
    memcpy(&hdr, item_ptr, sizeof(hdr));

    uint16_t vlen = SEG_HDR_VAL_LEN(hdr);
    if (vlen > buf_len) {
        if (value_len_out) *value_len_out = vlen;
        pthread_rwlock_unlock(&sc->locks[shard_id]);
        return -2;
    }

    memcpy(value_buf, item_ptr + sizeof(hdr) + SEG_HDR_KEY_LEN(hdr), vlen);
    if (value_len_out) *value_len_out = vlen;

    pthread_rwlock_unlock(&sc->locks[shard_id]);
    __atomic_fetch_add(&st->hits, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&st->gets, 1, __ATOMIC_RELAXED);
    return 0;
}

/* ── segcache_del ──────────────────────────────────────────────── */
int segcache_del(NexSegcache *sc, const char *key, uint16_t key_len) {
    if (!sc || !key) return -1;
    uint64_t hash64 = seg_hash(key, key_len);
    uint16_t key_fp = (uint16_t)(hash64 >> 48);
    int shard_id = (int)(hash64 % NEX_RCU_SHARDS);
    SegStats *st = &sc->shard_stats[shard_id];

    pthread_rwlock_wrlock(&sc->locks[shard_id]);
    uint32_t local_idx = (uint32_t)((hash64 / NEX_RCU_SHARDS) % sc->buckets_per_shard);
    uint32_t global_idx = (uint32_t)(shard_id * sc->buckets_per_shard) + local_idx;
    SegHashBucket *bkt = &sc->hash_table[global_idx];

    for (int s = 0; s < SEG_ITEMS_PER_BUCKET; s++) {
        if (!((bkt->occupancy >> s) & 1)) continue;
        if (bkt->entries[s].key_fp != key_fp) continue;

        /* PRIMA: si cancellava al primo match sul solo key_fp a 16 bit,
         * senza il memcmp della chiave reale che ht_find/segcache_exists
         * fanno correttamente. Con due chiavi diverse che finiscono nello
         * stesso bucket e condividono i 16 bit alti dell'hash (paradosso
         * del compleanno, comune con molte chiavi), DEL su una chiave
         * cancellava silenziosamente un'altra chiave del tutto estranea
         * (perdita dati). Verifica la chiave completa prima di rimuovere. */
        NexSegment *seg = &sc->segments[bkt->entries[s].seg_idx];
        uint8_t *item_ptr = seg->data + bkt->entries[s].item_offset;
        SegItemHeader hdr;
        memcpy(&hdr, item_ptr, sizeof(hdr));
        if (SEG_HDR_KEY_LEN(hdr) != key_len) continue;
        const char *stored_key = (const char *)(item_ptr + sizeof(hdr));
        if (memcmp(stored_key, key, key_len) != 0) continue;

        /* Trovato: rimuovi dall'hash table */
        bkt->occupancy &= ~(1u << s);
        st->dels++;
        pthread_rwlock_unlock(&sc->locks[shard_id]);
        return 1;
    }
    pthread_rwlock_unlock(&sc->locks[shard_id]);
    return 0;
}

int segcache_exists(NexSegcache *sc, const char *key, uint16_t key_len) {
    if (!sc || !key) return 0;
    uint64_t hash64 = seg_hash(key, key_len);
    uint16_t key_fp = (uint16_t)(hash64 >> 48);
    int shard_id = (int)(hash64 % NEX_RCU_SHARDS);

    /* Read-only under a read lock (like segcache_get): report expired entries
     * as absent without mutating the bucket; reclamation is lazy. */
    pthread_rwlock_rdlock(&sc->locks[shard_id]);
    uint32_t local_idx = (uint32_t)((hash64 / NEX_RCU_SHARDS) % sc->buckets_per_shard);
    uint32_t global_idx = (uint32_t)(shard_id * sc->buckets_per_shard) + local_idx;
    SegHashBucket *bkt = &sc->hash_table[global_idx];

    for (int s = 0; s < SEG_ITEMS_PER_BUCKET; s++) {
        if (!((bkt->occupancy >> s) & 1)) continue;
        if (bkt->entries[s].key_fp != key_fp) continue;

        /* Verifica chiave */
        NexSegment *seg = &sc->segments[bkt->entries[s].seg_idx];
        uint8_t *item_ptr = seg->data + bkt->entries[s].item_offset;
        SegItemHeader hdr;
        memcpy(&hdr, item_ptr, sizeof(hdr));

        if (SEG_HDR_KEY_LEN(hdr) == key_len) {
            const char *stored_key = (const char *)(item_ptr + sizeof(hdr));
            if (memcmp(stored_key, key, key_len) == 0) {
                /* Verifica TTL */
                uint32_t ttl_s = bucket_to_ttl_seconds(seg->ttl_bucket);
                if (ttl_s > 0) {
                    uint32_t expire = seg->create_time + ttl_s;
                    if (expire <= (uint32_t)time(NULL)) {
                        pthread_rwlock_unlock(&sc->locks[shard_id]);
                        return 0;
                    }
                }
                pthread_rwlock_unlock(&sc->locks[shard_id]);
                return 1;
            }
        }
    }
    pthread_rwlock_unlock(&sc->locks[shard_id]);
    return 0;
}

/* ── Expiration O(1): libera segmenti scaduti in tutti gli shard ─ */
uint32_t segcache_expire_segments(NexSegcache *sc) {
    if (!sc) return 0;
    uint32_t total_expired = 0;
    uint32_t now = seg_unix_now();

    for (int shard_id = 0; shard_id < NEX_RCU_SHARDS; shard_id++) {
        pthread_rwlock_wrlock(&sc->locks[shard_id]);
        for (uint32_t b = 0; b < SEG_TTL_BUCKETS; b++) {
            NexSegment *seg = sc->ttl_shards[shard_id][b];
            while (seg) {
                uint32_t ttl_s = bucket_to_ttl_seconds(b);
                uint32_t expire_time = seg->create_time + ttl_s;

                if (ttl_s > 0 && expire_time <= now) {
                    NexSegment *next = seg->next;
                    if (seg->prev)
                        seg->prev->next = seg->next;
                    else
                        sc->ttl_shards[shard_id][b] = seg->next;
                    if (seg->next) seg->next->prev = seg->prev;

                    /* NEX-VERA: MPSC Recovery 
                     * Molti shard restituiscono segmenti contemporaneamente (Many-Producers). */
                    uint32_t seg_idx = (uint32_t)(seg - sc->segments);
                    mpsc_node_t *node = (mpsc_node_t *)malloc(sizeof(mpsc_node_t));
                    node->data = (void *)(uintptr_t)seg_idx;
                    mpsc_enqueue(&sc->free_queue, node);
                    atomic_fetch_add(&sc->n_free, 1);

                    sc->shard_stats[shard_id].evictions_segment++;
                    sc->shard_stats[shard_id].expirations += seg->n_items;
                    total_expired += seg->n_items;
                    seg = next;
                } else {
                    seg = seg->next;
                }
            }
        }
        pthread_rwlock_unlock(&sc->locks[shard_id]);
    }
    return total_expired;
}

SegStats segcache_get_stats(NexSegcache *sc) {
    SegStats total = {0};
    if (!sc) return total;
    
    for (int i = 0; i < NEX_RCU_SHARDS; i++) {
        pthread_rwlock_rdlock(&sc->locks[i]);
        total.gets += sc->shard_stats[i].gets;
        total.sets += sc->shard_stats[i].sets;
        total.dels += sc->shard_stats[i].dels;
        total.hits += sc->shard_stats[i].hits;
        total.misses += sc->shard_stats[i].misses;
        total.evictions_segment += sc->shard_stats[i].evictions_segment;
        total.expirations += sc->shard_stats[i].expirations;
        total.bytes_stored += sc->shard_stats[i].bytes_stored;
        pthread_rwlock_unlock(&sc->locks[i]);
    }
    
    total.active_segments = sc->n_segments - atomic_load(&sc->n_free);

    if (total.gets > 0)
        total.hit_rate = (double)total.hits / (double)total.gets;
    
    return total;
}

void segcache_print_stats(NexSegcache *sc) {
    if (!sc) return;
    SegStats s = segcache_get_stats(sc);
    fprintf(stderr,
            "[NexCache Segcache] G3-GODMODE Sharded Stats (%d shards):\n"
            "  gets=%llu hits=%llu miss=%llu rate=%.2f%%\n"
            "  sets=%llu dels=%llu\n"
            "  evict_seg=%llu expire=%llu\n"
            "  active_segs=%u\n"
            "  bytes_stored=%llu\n",
            NEX_RCU_SHARDS,
            (unsigned long long)s.gets,
            (unsigned long long)s.hits,
            (unsigned long long)s.misses,
            s.hit_rate * 100.0,
            (unsigned long long)s.sets,
            (unsigned long long)s.dels,
            (unsigned long long)s.evictions_segment,
            (unsigned long long)s.expirations,
            s.active_segments,
            (unsigned long long)s.bytes_stored);
}

void segcache_destroy(NexSegcache *sc) {
    if (!sc) return;
    sc->running = 0;
    if (sc->reaper_thread) pthread_join(sc->reaper_thread, NULL);
    for (uint32_t i = 0; i < sc->n_segments; i++) free(sc->segments[i].data);
    free(sc->segments);

    /* Pulisce i nodi rimanenti della coda MPSC */
    mpsc_node_t *node;
    while ((node = mpsc_dequeue(&sc->free_queue))) free(node);

    for (int i = 0; i < NEX_RCU_SHARDS; i++) {
        free(sc->ttl_shards[i]);
        pthread_rwlock_destroy(&sc->locks[i]);
    }
    free(sc);
}
