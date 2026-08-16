/* NexCache VLL Transaction Manager — Header
 * Virtual Lock Layer — paper "VLL: a lock manager redesign
 * for main memory database systems" (Islam et al.)
 *
 * Ispirato da Dragonfly DB, con aggiunta "predictive lock ordering":
 * analizza pattern storici e pre-ordina i lock per minimizzare contesa.
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */
#ifndef NEXCACHE_VLL_H
#define NEXCACHE_VLL_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#define VLL_MAX_KEYS_PER_TXN 64
#define VLL_MAX_CONCURRENT_TXN 4096
#define VLL_TIMEOUT_US 10000 /* 10ms timeout per acquisizione */

typedef enum VLLLockType {
    VLL_LOCK_READ = 0,
    VLL_LOCK_WRITE = 1,
} VLLLockType;

typedef enum VLLStatus {
    VLL_OK = 0,
    VLL_CONFLICT = 1, /* Lock conflict, retry */
    VLL_TIMEOUT = 2,  /* Timeout acquisizione */
    VLL_ABORTED = 3,  /* Transazione abortita */
} VLLStatus;

typedef struct VLLKey {
    uint64_t key_hash;
    VLLLockType lock_type;
} VLLKey;

/* Pattern storico per predictive ordering */
typedef struct VLLPattern {
    uint64_t key_pair_hash; /* Hash della coppia di chiavi co-richieste */
    uint32_t count;         /* Numero di volte che appaiono insieme */
    uint32_t conflicts;     /* Conflitti registrati su questa coppia */
} VLLPattern;

typedef struct VLLRequest {
    uint64_t txn_id;
    uint16_t num_keys;
    VLLKey keys[VLL_MAX_KEYS_PER_TXN];
    VLLStatus status;
    void *callback_ctx;
    void (*callback)(struct VLLRequest *req);
    uint64_t submit_us;   /* Timestamp submission */
    uint64_t acquired_us; /* Timestamp acquisizione lock */
} VLLRequest;

typedef struct VLLStats {
    uint64_t txns_submitted;
    uint64_t txns_committed;
    uint64_t txns_aborted;
    uint64_t txns_timeout;
    uint64_t conflicts_resolved;
    uint64_t predictive_reorders; /* Volte che il reorder ha evitato conflitto */
    double avg_wait_us;
} VLLStats;

typedef struct VLLManager {
    /* Lock table: hash → contatore read/write */
    uint32_t *read_counts; /* Contatore lettori per slot */
    uint8_t *write_flags;  /* 1 = slot ha uno scrittore */
    uint32_t table_size;   /* Power of 2 */
    /* Protegge read_counts/write_flags: senza di esso, due transazioni
     * concorrenti possono entrambe leggere write_flags[slot]==0, decidere
     * entrambe di acquisire e scriverlo entrambe a 1 (TOCTOU) — il lock
     * manager stesso non garantiva l'esclusione mutua che dovrebbe fornire.
     * Tenuto solo per la durata della scansione/acquisizione di un
     * singolo tentativo, mai durante l'usleep di backoff. */
    pthread_mutex_t table_lock;

    /* Pattern history per predictive ordering */
    VLLPattern *patterns;
    uint32_t pattern_count;
    uint32_t pattern_cap;

    /* Statistiche */
    VLLStats stats;
    pthread_mutex_t stats_lock;

    /* Unique transaction ID */
    uint64_t next_txn_id;
} VLLManager;

/* ── API ────────────────────────────────────────────────────── */
VLLManager *vll_create(uint32_t table_size);
void vll_destroy(VLLManager *mgr);

/* Acquisisci lock per una transazione (blocking con timeout) */
VLLStatus vll_acquire(VLLManager *mgr, VLLRequest *req);

/* Rilascia tutti i lock della transazione */
void vll_release(VLLManager *mgr, VLLRequest *req);

/* Crea una VLLRequest e ottimizza l'ordinamento delle chiavi */
VLLRequest *vll_request_create(VLLManager *mgr,
                               uint64_t *key_hashes,
                               VLLLockType *lock_types,
                               uint16_t num_keys);
void vll_request_destroy(VLLRequest *req);

/* Statistiche */
VLLStats vll_get_stats(VLLManager *mgr);
void vll_print_stats(VLLManager *mgr);

#endif /* NEXCACHE_VLL_H */
