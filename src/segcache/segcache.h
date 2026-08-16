/* NexSegcache — Storage TTL-optimized (da Pelikan/CMU NSDI'21)
 * ============================================================
 * Ispirato da Segcache di Twitter/Carnegie Mellon University
 * (NSDI'21 Best Paper Award).
 *
 * Differenza fondamentale:
 *   Memcached (slab): raggruppa oggetti per DIMENSIONE → spreco con TTL variabili
 *   NexCache (dict):     overhead 64 bit per entry → +60% memoria sprecata
 *   NexSegcache:      raggruppa oggetti per TTL SIMILE → compaction efficiente
 *
 * Risultati documentati dal paper originale:
 *   - Metadati per oggetto: ~8 bytes vs 56 Memcached vs 64 NexCache
 *   - Risparmio memoria: fino al 60% per workload TTL-heavy
 *   - Scalabilità: 8x throughput di Memcached su 24 thread
 *   - Expiration O(1): libera un intero segmento in un colpo
 *
 * Quando NexCache usa NexSegcache invece di NexDashTable:
 *   - avg_object_size < 512 bytes E ttl_prevalence > 70%
 *   - Configurabile manualmente: `storage-engine segcache`
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */
#ifndef NEXCACHE_SEGCACHE_H
#define NEXCACHE_SEGCACHE_H

#include "../config.h"
#include <inttypes.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <stdatomic.h>
#include "../vera_lockfree.h"

/* ── Configurazione ─────────────────────────────────────────── */
#define SEG_DEFAULT_SIZE (1024 * 1024) /* 1MB per segmento */
#define SEG_MAX_SEGMENTS 65536
#define SEG_TTL_BUCKETS 1024  /* Bucket TTL: ogni bucket ≈ intervallo */
#define SEG_TTL_GRANULARITY 1 /* Secondi di granularità per bucket */
#define SEG_HASH_POWER 13     /* 2^13 = 8192 bucket PER SHARD */
#define SEG_BUCKETS_PER_SHARD (1 << SEG_HASH_POWER)
#define SEG_HASH_BUCKETS (SEG_BUCKETS_PER_SHARD * NEX_RCU_SHARDS)
#define SEG_ITEMS_PER_BUCKET 8 /* Bulk-chaining: 8 slot per bucket */

/* ── Item header (8 bytes totali — vs 56 Memcached, 64 NexCache) ─ */
/*
 * Layout compatto per oggetti piccoli con TTL:
 *  bit 63-48: key_hash[15:0]    (fingerprint per ridurre false positive)
 *  bit 47-32: key_len[15:0]     (max 65535 byte)
 *  bit 31-16: val_len[15:0]     (max 65535 byte)
 *  bit 15- 0: ttl_bucket[15:0]  (indice bucket TTL)
 */
typedef uint64_t SegItemHeader;

#define SEG_HDR_KEY_HASH(h) (((h) >> 48) & 0xFFFF)
#define SEG_HDR_KEY_LEN(h) (((h) >> 32) & 0xFFFF)
#define SEG_HDR_VAL_LEN(h) (((h) >> 16) & 0xFFFF)
#define SEG_HDR_TTL_BUCKET(h) ((h) & 0xFFFF)

/* ── Segmento: log di item con TTL simile ────────────────────── */
typedef struct NexSegment {
    uint8_t *data;           /* Buffer dati (item packed == header+key+value) */
    uint32_t data_size;      /* Dimensione totale buffer */
    uint32_t write_offset;   /* Offset prossima scrittura */
    uint32_t n_items;        /* Numero oggetti nel segmento */
    uint32_t ttl_bucket;     /* TTL bucket: tutti gli oggetti hanno TTL simile */
    uint32_t create_time;    /* Quando è stato creato */
    uint32_t evict_age;      /* Se molto vecchio, da evict */
    struct NexSegment *next; /* Lista per TTL bucket */
    struct NexSegment *prev;
    mpsc_node_t pool_node; /* NEX-VERA: Zero-malloc segment pool node */
} NexSegment;

/* ── Hash table entry (bulk-chaining, 8 slot per bucket) ──────── */
typedef struct SegHashEntry {
    uint16_t key_fp;      /* Fingerprint chiave (16 bit) */
    uint16_t seg_idx;     /* Indice del segmento */
    uint32_t item_offset; /* Offset dell'item nel segmento */
} SegHashEntry;

typedef struct SegHashBucket {
    SegHashEntry entries[SEG_ITEMS_PER_BUCKET];
    uint8_t occupancy; /* Bit mask slot occupati */
    uint8_t _pad[3];
} SegHashBucket;

/* ── Statistiche ─────────────────────────────────────────────── */
typedef struct SegStats {
    uint64_t gets;
    uint64_t sets;
    uint64_t dels;
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions_segment; /* Interi segmenti evict */
    uint64_t evictions_item;    /* Item singoli evict */
    uint64_t expirations;       /* Item scaduti rimossi */
    uint64_t bytes_stored;
    uint64_t bytes_freed;
    double hit_rate;
    uint32_t active_segments;
} SegStats;

/* ── NexSegcache (struttura principale) ─────────────────────── */
typedef struct NexSegcache {
    /* NEX-VERA: Lock-Free Segment Pool (MPSC-GODMODE) */
    NexSegment *segments; 
    uint32_t n_segments;
    _Atomic uint32_t n_free;
    mpsc_queue_t free_queue;

    /* Liste TTL per shard: riduce contesa su inserimento */
    NexSegment **ttl_shards[NEX_RCU_SHARDS]; /* Ogni shard ha i suoi SEG_TTL_BUCKETS */

    /* Hash table bulk-chaining (SHARDED: zero-contention) */
    SegHashBucket *hash_table;
    uint32_t buckets_per_shard;

    /* Gestione memoria */
    size_t max_memory;
    _Atomic size_t used_memory;

    /* Multi-Lock Architecture.
     * NEX: rwlock (was mutex) so concurrent GETs on the same shard proceed in
     * parallel across IO threads. Writers (set/del/expire) still exclude. */
    pthread_rwlock_t locks[NEX_RCU_SHARDS];
    int running;

    /* Reaper: chiama segcache_expire_segments() periodicamente. Senza di
     * esso i segmenti scaduti non vengono mai restituiti al pool libero
     * (nessun altro punto del codebase chiamava questa funzione, e il
     * design lazy-reclaim su GET/exists non mutando il bucket sotto read
     * lock — corretto per la concorrenza — significa che neanche le
     * letture liberano segmenti), quindi una volta esaurito il pool ogni
     * SET fallisce permanentemente con "Out of segments" anche se la
     * maggior parte dei dati è scaduta da tempo. Vedi
     * segcache_reaper_thread in segcache.c. */
    pthread_t reaper_thread;

    /* Statistiche per shard (zero contesa in update) */
    SegStats shard_stats[NEX_RCU_SHARDS];
} NexSegcache;

/* ── API ────────────────────────────────────────────────────── */
NexSegcache *segcache_create(size_t max_memory, uint32_t segment_size);
void segcache_destroy(NexSegcache *sc);

int segcache_set(NexSegcache *sc, const char *key, uint16_t key_len, const uint8_t *value, uint16_t value_len, uint32_t ttl_seconds);
int segcache_get(NexSegcache *sc, const char *key, uint16_t key_len, uint8_t *value_buf, uint16_t buf_len, uint16_t *value_len_out);
int segcache_del(NexSegcache *sc, const char *key, uint16_t key_len);
int segcache_exists(NexSegcache *sc, const char *key, uint16_t key_len);

/* Espira segmenti TTL-scaduti: O(1) per segmento */
uint32_t segcache_expire_segments(NexSegcache *sc);

SegStats segcache_get_stats(NexSegcache *sc);
void segcache_print_stats(NexSegcache *sc);

#endif /* NEXCACHE_SEGCACHE_H */
