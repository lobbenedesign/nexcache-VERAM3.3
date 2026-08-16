/* NexStorage — Narrow-Waist Storage API
 * ============================================================
 * Ispirato alla Tsavorite narrow-waist API di Microsoft Garnet,
 * implementata in C (non C#) — zero GC, zero pause.
 *
 * Principio architetturale (da Garnet):
 *   Il layer RESP/NexCache è costruito sopra NexStorage come strato SOTTILE.
 *   L'unico modo di accedere ai dati è attraverso NexStorageAPI.
 *   Nessun accesso diretto alle strutture interne.
 *
 * Implementazioni selezionabili a runtime:
 *   - NexDashTable: workload generale, massima throughput
 *   - NexSegcache:  workload TTL-heavy, oggetti piccoli (< 512B)
 *   - NexFlash:     dataset > RAM, su SSD/NVMe
 *   - NexCloudTier: dataset > SSD, su S3/GCS/Azure
 *
 * Il layer RESP non sa quale backend è in uso.
 * Cambio backend: 1 riga nel config file, senza ricompilare.
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */
#ifndef NEXCACHE_NEXSTORAGE_H
#define NEXCACHE_NEXSTORAGE_H

#include <stdint.h>
#include <stddef.h>

/* ── Risultato delle operazioni ─────────────────────────────── */
typedef enum NexStorageResult {
    NEXS_OK = 0,        /* Operazione riuscita */
    NEXS_NOT_FOUND = 1, /* Chiave non trovata */
    NEXS_EXPIRED = 2,   /* Chiave scaduta */
    NEXS_ERROR = 3,     /* Errore generico */
    NEXS_FULL = 4,      /* Storage pieno */
    NEXS_TOO_LARGE = 5, /* Valore troppo grande */
    NEXS_PENDING = 6,   /* Operazione asincrona in corso */
} NexStorageResult;

/* ── Tipo di dato (per Object Store) ─────────────────────────── */
typedef enum NexDataType {
    NEXDT_STRING = 0,
    NEXDT_HASH = 1,
    NEXDT_LIST = 2,
    NEXDT_SET = 3,
    NEXDT_ZSET = 4,
    NEXDT_STREAM = 5,
    NEXDT_JSON = 6,
    NEXDT_VECTOR = 7,
    NEXDT_CRDT = 8,
    NEXDT_UNKNOWN = 255,
} NexDataType;

/* ── Entry generica ritornata da get ─────────────────────────── */
typedef struct NexEntry {
    const uint8_t *value;
    uint32_t value_len;
    NexDataType type;
    int64_t ttl_ms;   /* -1 = no expiry, -2 = expired, >=0 = ms restanti */
    uint64_t version; /* Per CAS (Compare-And-Swap) */
} NexEntry;

/* ── Callback per operazioni Read-Modify-Write atomiche ─────── */
typedef NexStorageResult (*NexRMWCallback)(
    NexEntry *existing, /* Entry attuale (NULL se non esiste) */
    const void *input,  /* Input dell'operazione (es: delta per INCR) */
    void *output,       /* Output dell'operazione (es: nuovo valore) */
    void *ctx           /* Context opaco */
);

/* ── Callback per SCAN ──────────────────────────────────────── */
typedef void (*NexScanCallback)(
    const char *key,
    uint32_t key_len,
    const NexEntry *entry,
    void *ctx);

/* ── Statistiche storage (comune a tutti i backend) ─────────── */
typedef struct NexStorageStats {
    uint64_t gets;
    uint64_t sets;
    uint64_t dels;
    uint64_t hits;
    uint64_t misses;
    uint64_t rmw_ops;
    uint64_t evictions;
    uint64_t expirations;
    size_t used_bytes;
    size_t max_bytes;
    uint32_t item_count;
    double hit_rate;
    char backend_name[32]; /* "NexDashTable", "NexSegcache", ecc. */
} NexStorageStats;

/* ═══════════════════════════════════════════════════════════════
 * NexStorageAPI — interfaccia narrow-waist
 * Tutto il layer NexCache/RESP passa da qui. Mai accesso diretto.
 * ═════════════════════════════════════════════════════════════ */
typedef struct NexStorageAPI {
    const char *name; /* "NexDashTable", "NexSegcache", "NexFlash", "NexCloud" */

    /* ── Init/Destroy ──────────────────────────────────────── */
    void *(*create)(const char *config_str);
    void (*destroy)(void *backend);

    /* ── Operazioni base ───────────────────────────────────── */
    NexStorageResult (*get)(void *backend,
                            const char *key,
                            uint32_t key_len,
                            NexEntry *entry_out);

    NexStorageResult (*set)(void *backend,
                            const char *key,
                            uint32_t key_len,
                            const uint8_t *value,
                            uint32_t value_len,
                            NexDataType type,
                            int64_t ttl_ms);

    NexStorageResult (*del)(void *backend,
                            const char *key,
                            uint32_t key_len);

    int (*exists)(void *backend,
                  const char *key,
                  uint32_t key_len);

    /* ── Operazione atomica Read-Modify-Write ──────────────── */
    /* Usata per INCR, HSET, SADD, ZADD, LPUSH, SETIF, ecc.   */
    /* Garantisce atomicità senza lock visibili al chiamante.   */
    NexStorageResult (*rmw)(void *backend,
                            const char *key,
                            uint32_t key_len,
                            NexRMWCallback cb,
                            const void *input,
                            void *output,
                            void *ctx);

    /* ── TTL management ────────────────────────────────────── */
    NexStorageResult (*expire)(void *backend,
                               const char *key,
                               uint32_t key_len,
                               int64_t ttl_ms);

    int64_t (*ttl)(void *backend,
                   const char *key,
                   uint32_t key_len);

    /* ── Subkey TTL (Advanced Feature) ───────────────────────── */
    /* Usato per HEXPIRE, SEXPIRE, ZEXPIRE, ecc. (NexCache unique) */
    NexStorageResult (*subkey_expire)(void *backend,
                                      const char *key,
                                      uint32_t key_len,
                                      const char *subkey,
                                      uint32_t subkey_len,
                                      int64_t ttl_ms);

    int64_t (*subkey_ttl)(void *backend,
                          const char *key,
                          uint32_t key_len,
                          const char *subkey,
                          uint32_t subkey_len);

    /* ── Scan e iterazione ─────────────────────────────────── */
    NexStorageResult (*scan)(void *backend,
                             const char *pattern,
                             uint32_t pattern_len,
                             uint64_t cursor,
                             uint32_t max_results,
                             NexScanCallback cb,
                             void *ctx);

    /* ── Snapshot fork-less ────────────────────────────────── */
    NexStorageResult (*snapshot_start)(void *backend);
    NexStorageResult (*snapshot_delta)(void *backend,
                                       NexScanCallback cb,
                                       void *ctx);
    NexStorageResult (*snapshot_end)(void *backend);

    /* ── Statistiche ───────────────────────────────────────── */
    void (*stats)(void *backend, NexStorageStats *out);
    void (*flush)(void *backend); /* Svuota il database */
} NexStorageAPI;

/* ═══════════════════════════════════════════════════════════════
 * NexStorage — wrapper che usa un backend selezionato
 * ═════════════════════════════════════════════════════════════ */
typedef struct NexStorage {
    const NexStorageAPI *api; /* Backend selezionato */
    void *backend;            /* Handle opaco al backend */

    /* Dual-Store Design (da Garnet):
     *   main_store:   ottimizzato per string operations (raw bytes)
     *   object_store: ottimizzato per tipi complessi (Hash, Set, List...)
     * I due store condividono un unico operation log.
     */
    const NexStorageAPI *main_api;
    void *main_backend; /* NexDashTable o NexSegcache */

    const NexStorageAPI *object_api;
    void *object_backend; /* Sempre NexDashTable per tipi complessi */

    /* Shared operation log (per replication e persistence) */
    uint64_t *op_log;
    uint64_t op_log_seq;
} NexStorage;

/* ── Backend registration ─────────────────────────────────────── */
extern const NexStorageAPI NexDashTableAPI;
extern const NexStorageAPI NexSegcacheAPI;
extern const NexStorageAPI NexCloudTierAPI;
extern const NexStorageAPI NexFlashAPI;

/* ── Funzioni di alto livello ────────────────────────────────── */
NexStorage *nexstorage_create(const char *backend_name,
                              const char *config_str);
void nexstorage_destroy(NexStorage *ns);

/* Wrapper inline per semplicità d'uso: */
static inline NexStorageResult
nexstorage_get(NexStorage *ns, const char *key, uint32_t key_len, NexEntry *out) {
    if (!ns || !ns->main_api || !ns->object_api) return NEXS_ERROR;

    /* Prova prima nel main store (ottimizzato per stringhe/hot-data) */
    NexStorageResult res = ns->main_api->get(ns->main_backend, key, key_len, out);
    if (res == NEXS_OK) return NEXS_OK;

    /* Se non trovato, cerca nell'object store (Hash, Set, List...) */
    return ns->object_api->get(ns->object_backend, key, key_len, out);
}

static inline NexStorageResult
nexstorage_set(NexStorage *ns, const char *key, uint32_t key_len, const uint8_t *value, uint32_t value_len, NexDataType type, int64_t ttl_ms) {
    if (!ns || !ns->main_api || !ns->object_api) return NEXS_ERROR;

    /* Dual-Store routing: */
    if (type == NEXDT_STRING) {
        return ns->main_api->set(ns->main_backend, key, key_len, value, value_len, type, ttl_ms);
    } else {
        return ns->object_api->set(ns->object_backend, key, key_len, value, value_len, type, ttl_ms);
    }
}

static inline NexStorageResult
nexstorage_del(NexStorage *ns, const char *key, uint32_t key_len) {
    if (!ns || !ns->main_api || !ns->object_api) return NEXS_ERROR;
    /* NEX-PERF: prima cancellava SEMPRE da entrambi gli store, anche
     * quando il chiamante non conosce il tipo — "per sicurezza". Ma una
     * chiave è o una stringa (main_api/segcache) o un tipo complesso
     * (object_api/nexdash), mai entrambe contemporaneamente: se il primo
     * delete trova ed elimina la chiave, il secondo store non può
     * contenerla e la seconda chiamata è lavoro sprecato al 100%.
     * Misurato con `sample` sotto carico SET puro: nexdash_del appariva
     * come hotspot reale (292 campioni) nonostante SET scriva SOLO
     * stringhe — ogni SET pagava un hash + una ricerca NEON nel bucket
     * di NexDashTable che falliva SEMPRE. Ora: prova prima il main_api
     * (store più caldo, dove vive la stragrande maggioranza delle chiavi
     * in un workload tipico); se trova ed elimina, salta l'object_api. */
    NexStorageResult r1 = ns->main_api->del(ns->main_backend, key, key_len);
    if (r1 == NEXS_OK) return NEXS_OK;
    NexStorageResult r2 = ns->object_api->del(ns->object_backend, key, key_len);
    return r2 == NEXS_OK ? NEXS_OK : NEXS_NOT_FOUND;
}

static inline NexStorageResult
nexstorage_rmw(NexStorage *ns, const char *key, uint32_t key_len, NexRMWCallback cb, const void *input, void *output, void *ctx) {
    if (!ns || !ns->main_api || !ns->object_api) return NEXS_ERROR;
    /* RMW solitamente usato per update in-place su object store (es CRDT) */
    if (ns->object_api->rmw)
        return ns->object_api->rmw(ns->object_backend, key, key_len, cb, input, output, ctx);
    return NEXS_ERROR;
}

static inline NexStorageResult
nexstorage_subkey_expire(NexStorage *ns, const char *key, uint32_t key_len, const char *subkey, uint32_t subkey_len, int64_t ttl_ms) {
    if (!ns || !ns->object_api || !ns->object_api->subkey_expire) return NEXS_ERROR;
    return ns->object_api->subkey_expire(ns->object_backend, key, key_len, subkey, subkey_len, ttl_ms);
}

static inline int64_t
nexstorage_subkey_ttl(NexStorage *ns, const char *key, uint32_t key_len, const char *subkey, uint32_t subkey_len) {
    if (!ns || !ns->object_api || !ns->object_api->subkey_ttl) return -1;
    return ns->object_api->subkey_ttl(ns->object_backend, key, key_len, subkey, subkey_len);
}

static inline int
nexstorage_exists(NexStorage *ns, const char *key, uint32_t key_len) {
    if (!ns || !ns->main_api || !ns->object_api) return 0;
    if (ns->main_api->exists(ns->main_backend, key, key_len)) return 1;
    return ns->object_api->exists(ns->object_backend, key, key_len);
}

/* ── Selezione backend dell'implementazione ─────────────────── */
NexStorage *nexstorage_create(const char *backend_name,
                              const char *config_str);
void nexstorage_destroy(NexStorage *ns);

#endif /* NEXCACHE_NEXSTORAGE_H */
