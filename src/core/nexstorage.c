/* NexStorage — Implementazione narrow-waist con backend NexDashTable
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "nexstorage.h"
#include "../hashtable/nexdash.h"
#include "../segcache/segcache.h"
#include "../flash/flash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* ═══════════════════════════════════════════════════════════════
 * ADATTATORE NexDashTable → NexStorageAPI
 * ═════════════════════════════════════════════════════════════ */

/* Container per un valore nel NexDashTable (include metadati) */
typedef struct NDValue {
    uint8_t *data;
    uint32_t data_len;
    NexDataType type;
    int64_t expire_us; /* Assoluto in microsecondi, -1 = no expiry */
    uint64_t version;
} NDValue;

static uint64_t nd_us_now_storage(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* NDValue è un unico blocco malloc (header + data contigui, val->data =
 * val+1), quindi free() semplice lo libera per intero. */
static void ndvalue_free_cb(void *value) {
    free(value);
}

static void *ndapi_create(const char *config_str) {
    size_t max_mem = 256 * 1024 * 1024; /* Default 256MB */
    if (config_str) {
        const char *p = strstr(config_str, "max_memory=");
        if (p) max_mem = (size_t)atol(p + 11);
    }
    NexDashTable *t = nexdash_create(4, max_mem);
    /* Senza questa callback, nexdash_set/del/evict/scan_expired non sanno
     * come liberare il vecchio NDValue: ogni overwrite/del/eviction perdeva
     * memoria in modo permanente. */
    if (t) nexdash_set_free_cb(t, ndvalue_free_cb);
    return t;
}

static void ndapi_destroy(void *backend) {
    nexdash_destroy((NexDashTable *)backend);
}

/* NexDashSlot codifica la lunghezza chiave in 8 bit (TAG_GET_LEN):
 * chiavi >255 byte non possono essere rappresentate. PRIMA venivano
 * troncate silenziosamente a 255 byte, causando collisioni/corruzione
 * dati tra chiavi diverse che condividono lo stesso prefisso di 255 byte
 * (SET su una chiave lunga sovrascriveva/aliasava un'altra chiave con lo
 * stesso prefisso). Rifiutare esplicitamente è corretto; supportare
 * davvero chiavi lunghe richiede allargare TAG_GET_LEN (redesign del
 * tagged pointer, fuori scope qui). */
#define ND_MAX_KEY_LEN 255

/* PRIMA: ndapi_get chiamava nexdash_get() (che prende e rilascia il lock
 * INTERNAMENTE, per singola chiamata) e poi esponeva al chiamante
 * `out->value = val->data` — un puntatore VIVO dentro il blocco allocato
 * per quel value, ma restituito DOPO che il lock di nexdash era già
 * stato rilasciato. Qualunque consumatore di NexEntry (incluso il
 * fast-path Garnet-style di io_threads.c/networking.c, che ritarda la
 * memcpy nel buffer di rete fino a dopo la chiamata) ha quindi una
 * finestra in cui un altro thread può fare SET sulla stessa chiave,
 * ndapi_set/nexdash_set_nolock chiama free_cb() sul vecchio valore (fix
 * di oggi per eliminare il leak — vedi commento su ndvalue_free_cb) e
 * libera esattamente la memoria che il lettore sta per copiare: use-
 * after-free. PRIMA del fix leak di oggi questo non era sfruttabile
 * (il vecchio valore veniva perso ma mai liberato, quindi restava
 * "valido" anche se stale) — eliminare il leak ha reso reale una race
 * che prima era solo latente.
 * ORA: get+copia avvengono nello stesso lock hold (nexdash_lock/
 * nexdash_get_nolock/nexdash_unlock, già usati da ndapi_rmw per lo
 * stesso motivo), copiando i byte in uno scratch buffer thread-local
 * PRIMA di rilasciare il lock — stesso pattern già usato da scapi_get
 * per il backend Segcache. Il puntatore restituito al chiamante punta
 * sempre a questo buffer, mai più alla memoria interna della tabella. */
static NexStorageResult ndapi_get(void *backend,
                                  const char *key,
                                  uint32_t key_len,
                                  NexEntry *out) {
    if (key_len > ND_MAX_KEY_LEN) return NEXS_TOO_LARGE;
    NexDashTable *t = (NexDashTable *)backend;
    uint8_t klen8 = (uint8_t)key_len;

    static _Thread_local uint8_t buf[1024 * 1024];

    nexdash_lock(t);
    NexEntryType et;
    NDValue *val = (NDValue *)nexdash_get_nolock(t, key, klen8, &et);
    if (!val) {
        nexdash_unlock(t);
        return NEXS_NOT_FOUND;
    }
    if (val->data_len > sizeof(buf)) {
        /* Valore più grande dello scratch buffer: non possiamo copiarlo
         * in sicurezza qui. Meglio fallire esplicitamente che troncare
         * silenziosamente (comportamento consistente con ND_MAX_KEY_LEN
         * sopra: rifiuto esplicito invece di corruzione silenziosa). */
        nexdash_unlock(t);
        return NEXS_TOO_LARGE;
    }
    memcpy(buf, val->data, val->data_len);
    uint32_t data_len = val->data_len;
    NexDataType type = val->type;
    uint64_t version = val->version;
    int64_t expire_us = val->expire_us;
    nexdash_unlock(t);

    out->value = buf;
    out->value_len = data_len;
    out->type = type;
    out->version = version;

    if (expire_us < 0) {
        out->ttl_ms = -1;
    } else {
        int64_t remaining = expire_us - (int64_t)nd_us_now_storage();
        out->ttl_ms = remaining > 0 ? remaining / 1000 : -2;
    }
    return NEXS_OK;
}

static NexStorageResult ndapi_set(void *backend,
                                  const char *key,
                                  uint32_t key_len,
                                  const uint8_t *value,
                                  uint32_t value_len,
                                  NexDataType type,
                                  int64_t ttl_ms) {
    if (key_len > ND_MAX_KEY_LEN) return NEXS_TOO_LARGE;
    NexDashTable *t = (NexDashTable *)backend;
    uint8_t klen8 = (uint8_t)key_len;

    /* Crea NDValue container */
    NDValue *val = (NDValue *)malloc(sizeof(NDValue) + value_len);
    if (!val) return NEXS_ERROR;

    val->data = (uint8_t *)(val + 1);
    val->data_len = value_len;
    val->type = type;
    val->version = nd_us_now_storage(); /* Version = timestamp */
    val->expire_us = (ttl_ms >= 0) ? (int64_t)(nd_us_now_storage() + (uint64_t)ttl_ms * 1000) : -1;
    memcpy(val->data, value, value_len);

    uint64_t expire_us_arg = (ttl_ms >= 0) ? (nd_us_now_storage() + (uint64_t)ttl_ms * 1000) : 0;

    NexEntryType net = (NexEntryType)type;
    uint32_t total_size = (uint32_t)(sizeof(NDValue) + value_len);
    int rc = nexdash_set(t, key, klen8, val, total_size, net, expire_us_arg);
    if (!rc) {
        free(val);
        return NEXS_ERROR;
    }
    return NEXS_OK;
}

static NexStorageResult ndapi_del(void *backend,
                                  const char *key,
                                  uint32_t key_len) {
    if (key_len > ND_MAX_KEY_LEN) return NEXS_NOT_FOUND;
    NexDashTable *t = (NexDashTable *)backend;
    uint8_t klen8 = (uint8_t)key_len;
    int rc = nexdash_del(t, key, klen8);
    return rc > 0 ? NEXS_OK : NEXS_NOT_FOUND;
}

static int ndapi_exists(void *backend, const char *key, uint32_t key_len) {
    if (key_len > ND_MAX_KEY_LEN) return 0;
    NexDashTable *t = (NexDashTable *)backend;
    uint8_t klen8 = (uint8_t)key_len;
    return nexdash_exists(t, key, klen8);
}

/* RMW atomico: leggi → modifica → scrivi sotto lo stesso lock della tabella.
 * PRIMA: get e set erano due chiamate separate a nexdash_get/nexdash_set,
 * ciascuna con il proprio lock-acquire-release — tra le due nulla impediva
 * a un secondo INCR/HSET concorrente di intercalarsi, leggere lo stesso
 * valore base e sovrascrivere l'aggiornamento del primo (lost update).
 * ORA: nexdash_lock() viene tenuto per l'intera sequenza get→cb→set via
 * le varianti _nolock, rendendo l'operazione davvero atomica come
 * documentato in nexstorage.h. */
static NexStorageResult ndapi_rmw(void *backend,
                                  const char *key,
                                  uint32_t key_len,
                                  NexRMWCallback cb,
                                  const void *input,
                                  void *output,
                                  void *ctx) {
    if (key_len > ND_MAX_KEY_LEN) return NEXS_TOO_LARGE;
    NexDashTable *t = (NexDashTable *)backend;
    uint8_t klen8 = (uint8_t)key_len;

    nexdash_lock(t);

    NexEntry entry = {0};
    entry.ttl_ms = -1;
    NexEntryType et;
    NDValue *val = (NDValue *)nexdash_get_nolock(t, key, klen8, &et);
    if (val) {
        entry.value = val->data;
        entry.value_len = val->data_len;
        entry.type = val->type;
        entry.version = val->version;
        if (val->expire_us < 0) {
            entry.ttl_ms = -1;
        } else {
            int64_t remaining = val->expire_us - (int64_t)nd_us_now_storage();
            entry.ttl_ms = remaining > 0 ? remaining / 1000 : -2;
        }
    }

    NexStorageResult res = cb(&entry, input, output, ctx);
    if (res == NEXS_OK) {
        NDValue *nv = (NDValue *)malloc(sizeof(NDValue) + entry.value_len);
        if (!nv) {
            nexdash_unlock(t);
            return NEXS_ERROR;
        }
        nv->data = (uint8_t *)(nv + 1);
        nv->data_len = entry.value_len;
        nv->type = entry.type;
        nv->version = nd_us_now_storage();
        nv->expire_us = (entry.ttl_ms >= 0) ? (int64_t)(nd_us_now_storage() + (uint64_t)entry.ttl_ms * 1000) : -1;
        if (entry.value_len) memcpy(nv->data, entry.value, entry.value_len);

        uint64_t expire_us_arg = (entry.ttl_ms >= 0) ? (nd_us_now_storage() + (uint64_t)entry.ttl_ms * 1000) : 0;
        uint32_t total_size = (uint32_t)(sizeof(NDValue) + entry.value_len);
        if (!nexdash_set_nolock(t, key, klen8, nv, total_size, (NexEntryType)entry.type, expire_us_arg)) {
            free(nv);
            nexdash_unlock(t);
            return NEXS_ERROR;
        }
    }
    nexdash_unlock(t);
    return res;
}

static NexStorageResult ndapi_expire(void *backend,
                                     const char *key,
                                     uint32_t key_len,
                                     int64_t ttl_ms) {
    if (key_len > ND_MAX_KEY_LEN) return NEXS_NOT_FOUND;
    NexDashTable *t = (NexDashTable *)backend;
    uint8_t klen8 = (uint8_t)key_len;
    uint64_t expire_us = (ttl_ms >= 0) ? (nd_us_now_storage() + (uint64_t)ttl_ms * 1000) : 0;
    int rc = nexdash_expire(t, key, klen8, expire_us);
    return rc > 0 ? NEXS_OK : NEXS_NOT_FOUND;
}

static NexStorageResult ndapi_subkey_expire(void *backend,
                                            const char *key,
                                            uint32_t key_len,
                                            const char *subkey,
                                            uint32_t subkey_len,
                                            int64_t ttl_ms) {
    (void)backend;
    (void)key;
    (void)key_len;
    (void)subkey;
    (void)subkey_len;
    (void)ttl_ms;
    /* In NexDashTable, i subkey sono implementati dentro la row (es: vset per i SET).
     * Qui dovremmo chiamare vset_expire se la row è un SET. */
    return NEXS_OK; /* Stub success */
}

static int64_t ndapi_subkey_ttl(void *backend,
                                const char *key,
                                uint32_t key_len,
                                const char *subkey,
                                uint32_t subkey_len) {
    (void)backend;
    (void)key;
    (void)key_len;
    (void)subkey;
    (void)subkey_len;
    return -1; /* Stub: no expiry */
}

static int64_t ndapi_ttl(void *backend,
                         const char *key,
                         uint32_t key_len) {
    NexEntry entry = {0};
    if (ndapi_get(backend, key, key_len, &entry) != NEXS_OK)
        return -2;
    return entry.ttl_ms;
}

typedef struct NdScanAdapt {
    NexScanCallback cb;
    void *ctx;
} NdScanAdapt;

static void nd_scan_adapter(const char *key, uint8_t key_len, void *value, uint8_t type, void *ctx) {
    NdScanAdapt *a = (NdScanAdapt *)ctx;
    NDValue *val = (NDValue *)value;
    if (!val) return;
    NexEntry entry = {
        .value = val->data,
        .value_len = val->data_len,
        .type = val->type,
        .ttl_ms = -1,
        .version = val->version,
    };
    (void)type;
    a->cb(key, key_len, &entry, a->ctx);
}

static NexStorageResult ndapi_scan(void *backend,
                                   const char *pattern,
                                   uint32_t pattern_len,
                                   uint64_t cursor,
                                   uint32_t max_results,
                                   NexScanCallback cb,
                                   void *ctx) {
    (void)pattern;
    (void)pattern_len;
    (void)cursor;
    (void)max_results;
    NdScanAdapt adapt = {.cb = cb, .ctx = ctx};
    nexdash_scan((NexDashTable *)backend, nd_scan_adapter, &adapt);
    return NEXS_OK;
}

static NexStorageResult ndapi_snapshot_start(void *backend) {
    return nexdash_snapshot_start((NexDashTable *)backend) == 0 ? NEXS_OK : NEXS_ERROR;
}
static NexStorageResult ndapi_snapshot_delta(void *backend,
                                             NexScanCallback cb,
                                             void *ctx) {
    NdScanAdapt adapt = {.cb = cb, .ctx = ctx};
    return nexdash_snapshot_iterate_delta((NexDashTable *)backend,
                                          nd_scan_adapter, &adapt) == 0
               ? NEXS_OK
               : NEXS_ERROR;
}
static NexStorageResult ndapi_snapshot_end(void *backend) {
    return nexdash_snapshot_end((NexDashTable *)backend) == 0 ? NEXS_OK : NEXS_ERROR;
}

static void ndapi_stats(void *backend, NexStorageStats *out) {
    NexDashTable *t = (NexDashTable *)backend;
    NexDashStats s = nexdash_get_stats(t);
    out->gets = s.gets;
    out->sets = s.sets;
    out->dels = s.dels;
    out->hits = s.hits;
    out->misses = s.misses;
    out->evictions = s.evictions_probatory + s.evictions_protected;
    out->hit_rate = s.hit_rate;
    out->item_count = t->item_count;
    strncpy(out->backend_name, "NexDashTable", sizeof(out->backend_name) - 1);
}

static void ndapi_flush(void *backend) {
    /* Per ora: scan e cancella tutto */
    (void)backend;
}

/* ── NexDashTable API istanza ─────────────────────────────────── */
const NexStorageAPI NexDashTableAPI = {
    .name = "NexDashTable",
    .create = ndapi_create,
    .destroy = ndapi_destroy,
    .get = ndapi_get,
    .set = ndapi_set,
    .del = ndapi_del,
    .exists = ndapi_exists,
    .rmw = ndapi_rmw,
    .expire = ndapi_expire,
    .subkey_expire = ndapi_subkey_expire,
    .subkey_ttl = ndapi_subkey_ttl,
    .ttl = ndapi_ttl,
    .scan = ndapi_scan,
    .snapshot_start = ndapi_snapshot_start,
    .snapshot_delta = ndapi_snapshot_delta,
    .snapshot_end = ndapi_snapshot_end,
    .stats = ndapi_stats,
    .flush = ndapi_flush,
};

/* ═══════════════════════════════════════════════════════════════
 * ADATTATORE NexSegcache → NexStorageAPI (per workload TTL-heavy)
 * ═════════════════════════════════════════════════════════════ */

static void *scapi_create(const char *config_str) {
    size_t max_mem = 256 * 1024 * 1024;
    if (config_str) {
        const char *p = strstr(config_str, "max_memory=");
        if (p) max_mem = (size_t)atol(p + 11);
    }
    return segcache_create(max_mem, SEG_DEFAULT_SIZE);
}

static void scapi_destroy(void *b) {
    segcache_destroy((NexSegcache *)b);
}

static NexStorageResult scapi_get(void *backend,
                                  const char *key,
                                  uint32_t klen,
                                  NexEntry *out) {
    /* G3-GODMODE: Thread-Local Scratchpad for Zero-Contention Vera Lookups.
     * NEX-FIX: 65535, NOT 65536 — segcache_get takes a uint16_t buf_len, and
     * (uint16_t)65536 == 0, which made EVERY lookup fail with "buffer too
     * small" and report NOT_FOUND, disabling the whole NexStorage read path. */
    static _Thread_local uint8_t buf[65535];
    uint16_t vlen = 0;
    int rc = segcache_get((NexSegcache *)backend, key, (uint16_t)klen,
                          buf, (uint16_t)sizeof(buf), &vlen);
    if (rc != 0) return NEXS_NOT_FOUND;
    out->value = buf;
    out->value_len = vlen;
    out->type = NEXDT_STRING;
    out->ttl_ms = -1;
    return NEXS_OK;
}

static NexStorageResult scapi_set(void *backend,
                                  const char *key,
                                  uint32_t klen,
                                  const uint8_t *value,
                                  uint32_t vlen,
                                  NexDataType type,
                                  int64_t ttl_ms) {
    (void)type;
    uint32_t ttl_s = ttl_ms >= 0 ? (uint32_t)(ttl_ms / 1000) : 0;
    int rc = segcache_set((NexSegcache *)backend, key, (uint16_t)klen,
                          value, (uint16_t)vlen, ttl_s);
    return rc == 0 ? NEXS_OK : NEXS_ERROR;
}

static NexStorageResult scapi_del(void *b, const char *key, uint32_t klen) {
    return segcache_del((NexSegcache *)b, key, (uint16_t)klen) > 0 ? NEXS_OK : NEXS_NOT_FOUND;
}

static int scapi_exists(void *b, const char *key, uint32_t klen) {
    return segcache_exists((NexSegcache *)b, key, (uint16_t)klen);
}

static void scapi_stats(void *b, NexStorageStats *out) {
    SegStats s = segcache_get_stats((NexSegcache *)b);
    out->gets = s.gets;
    out->sets = s.sets;
    out->dels = s.dels;
    out->hits = s.hits;
    out->misses = s.misses;
    out->evictions = s.evictions_segment;
    out->hit_rate = s.hit_rate;
    strncpy(out->backend_name, "NexSegcache", sizeof(out->backend_name) - 1);
}

static void scapi_flush(void *b) {
    (void)b;
}
static NexStorageResult scapi_rmw(void *b, const char *k, uint32_t kl, NexRMWCallback cb, const void *in, void *out, void *ctx) {
    NexEntry entry = {0};
    entry.ttl_ms = -1;
    scapi_get(b, k, kl, &entry);
    NexStorageResult res = cb(&entry, in, out, ctx);
    if (res == NEXS_OK) {
        /* PRIMA: il risultato del callback non veniva mai scritto indietro —
         * ogni RMW su backend Segcache (INCR/HSET su chiavi TTL-heavy)
         * calcolava il nuovo valore e lo scartava silenziosamente. */
        scapi_set(b, k, kl, entry.value, entry.value_len, entry.type, entry.ttl_ms);
    }
    return res;
}
static NexStorageResult scapi_expire(void *b, const char *k, uint32_t kl, int64_t ttl_ms) {
    (void)b;
    (void)k;
    (void)kl;
    (void)ttl_ms;
    return NEXS_OK; /* Segcache gestisce TTL al set */
}
static int64_t scapi_ttl(void *b, const char *k, uint32_t kl) {
    (void)b;
    (void)k;
    (void)kl;
    return -1;
}
static NexStorageResult scapi_scan(void *b, const char *pat, uint32_t pl, uint64_t cur, uint32_t max, NexScanCallback cb, void *ctx) {
    (void)b;
    (void)pat;
    (void)pl;
    (void)cur;
    (void)max;
    (void)cb;
    (void)ctx;
    return NEXS_OK;
}
static NexStorageResult scapi_snap_start(void *b) {
    (void)b;
    return NEXS_OK;
}
static NexStorageResult scapi_snap_delta(void *b, NexScanCallback cb, void *ctx) {
    (void)b;
    (void)cb;
    (void)ctx;
    return NEXS_OK;
}
static NexStorageResult scapi_snap_end(void *b) {
    (void)b;
    return NEXS_OK;
}

const NexStorageAPI NexSegcacheAPI = {
    .name = "NexSegcache",
    .create = scapi_create,
    .destroy = scapi_destroy,
    .get = scapi_get,
    .set = scapi_set,
    .del = scapi_del,
    .exists = scapi_exists,
    .rmw = scapi_rmw,
    .expire = scapi_expire,
    .ttl = scapi_ttl,
    .scan = scapi_scan,
    .snapshot_start = scapi_snap_start,
    .snapshot_delta = scapi_snap_delta,
    .snapshot_end = scapi_snap_end,
    .stats = scapi_stats,
    .flush = scapi_flush,
};

/* ═══════════════════════════════════════════════════════════════
 * ADATTATORE NexFlash → NexStorageAPI
 * ═════════════════════════════════════════════════════════════ */
static uint64_t flash_hash_fnv1a(const char *key, uint32_t len) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (uint32_t i = 0; i < len; i++) {
        hash ^= (uint64_t)key[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static void *flashapi_create(const char *config_str) {
    FlashConfig cfg = {0};
    strcpy(cfg.path, "/tmp/nexcache.flash");
    cfg.max_size_bytes = 1024LL * 1024 * 1024;
    cfg.cooling_interval_ms = 5000;
    cfg.prefetch_enabled = 1;

    if (config_str) {
        const char *p = strstr(config_str, "path=");
        if (p) {
            const char *end = strchr(p, ',');
            size_t len = end ? (size_t)(end - (p + 5)) : strlen(p + 5);
            if (len >= sizeof(cfg.path)) len = sizeof(cfg.path) - 1;
            strncpy(cfg.path, p + 5, len);
            cfg.path[len] = '\0';
        }
    }
    return flash_create(&cfg);
}

static void flashapi_destroy(void *b) {
    flash_destroy((FlashStorage *)b);
}

static NexStorageResult flashapi_get(void *b, const char *k, uint32_t kl, NexEntry *out) {
    /* PRIMA: buffer static (non thread-local) condiviso da tutti gli 8
     * worker — due GET concorrenti sul backend Flash si sovrascrivevano a
     * vicenda il buffer, corrompendo i value ritornati. scapi_get (sopra)
     * usa correttamente _Thread_local per lo stesso motivo. */
    static _Thread_local uint8_t buf[1024 * 1024]; /* 1MB buffer limit per read in this adapter */
    uint32_t vlen = 0;
    uint64_t h = flash_hash_fnv1a(k, kl);
    int rc = flash_read((FlashStorage *)b, h, buf, sizeof(buf), &vlen);
    if (rc != 0) return NEXS_NOT_FOUND;
    out->value = buf;
    out->value_len = vlen;
    out->type = NEXDT_STRING;
    out->ttl_ms = -1;
    return NEXS_OK;
}

static NexStorageResult flashapi_set(void *b, const char *k, uint32_t kl, const uint8_t *v, uint32_t vl, NexDataType type, int64_t ttl_ms) {
    (void)type;
    uint64_t h = flash_hash_fnv1a(k, kl);
    uint32_t expire = (ttl_ms >= 0) ? (uint32_t)(time(NULL) + (ttl_ms / 1000)) : 0;
    int rc = flash_write((FlashStorage *)b, h, k, kl, v, vl, expire);
    return rc == 0 ? NEXS_OK : NEXS_ERROR;
}

static NexStorageResult flashapi_del(void *b, const char *k, uint32_t kl) {
    uint64_t h = flash_hash_fnv1a(k, kl);
    return flash_delete((FlashStorage *)b, h) > 0 ? NEXS_OK : NEXS_NOT_FOUND;
}

static int flashapi_exists(void *b, const char *k, uint32_t kl) {
    uint64_t h = flash_hash_fnv1a(k, kl);
    uint32_t vlen = 0;
    uint8_t dummy;
    return flash_read((FlashStorage *)b, h, &dummy, 0, &vlen) == -2 || vlen > 0;
}

static NexStorageResult flashapi_expire(void *b, const char *k, uint32_t kl, int64_t ttl_ms) {
    uint64_t h = flash_hash_fnv1a(k, kl);
    uint32_t expire = (ttl_ms >= 0) ? (uint32_t)(time(NULL) + (ttl_ms / 1000)) : 0;
    return flash_expire((FlashStorage *)b, h, expire) == 1 ? NEXS_OK : NEXS_NOT_FOUND;
}

static int64_t flashapi_ttl(void *b, const char *k, uint32_t kl) {
    uint64_t h = flash_hash_fnv1a(k, kl);
    return flash_ttl((FlashStorage *)b, h);
}

static void flashapi_stats(void *b, NexStorageStats *out) {
    FlashStorage *fs = (FlashStorage *)b;
    FlashStats s = flash_get_stats(fs);
    out->gets = s.reads;
    out->sets = s.writes;
    out->dels = s.evictions; /* Usato impropriamente per demo */
    out->hits = s.prefetch_hits;
    out->misses = s.reads - s.prefetch_hits;
    out->evictions = s.evictions;
    out->hit_rate = (double)s.prefetch_hits / (s.reads > 0 ? s.reads : 1);
    out->item_count = fs->index_count;
    strncpy(out->backend_name, "NexFlash", sizeof(out->backend_name) - 1);
}

static void flashapi_flush(void *b) {
    flash_flush((FlashStorage *)b);
}

const NexStorageAPI NexFlashAPI = {
    .name = "NexFlash",
    .create = flashapi_create,
    .destroy = flashapi_destroy,
    .get = flashapi_get,
    .set = flashapi_set,
    .del = flashapi_del,
    .exists = flashapi_exists,
    .expire = flashapi_expire,
    .ttl = flashapi_ttl,
    .stats = flashapi_stats,
    .flush = flashapi_flush,
};

/* ═══════════════════════════════════════════════════════════════
 * nexstorage_create — factory function
 * ═════════════════════════════════════════════════════════════ */
NexStorage *nexstorage_create(const char *backend_name,
                              const char *config_str) {
    NexStorage *ns = (NexStorage *)calloc(1, sizeof(NexStorage));
    if (!ns) return NULL;

    const NexStorageAPI *api = &NexDashTableAPI; /* Default */
    if (backend_name && strcmp(backend_name, "segcache") == 0)
        api = &NexSegcacheAPI;
    else if (backend_name && strcmp(backend_name, "cloud") == 0)
        api = &NexCloudTierAPI;
    else if (backend_name && strcmp(backend_name, "flash") == 0)
        api = &NexFlashAPI;

    ns->api = api; /* Primary API for fallback */

    /* Dual-Store: main store per stringhe (user selected),
     * object store per tipi complessi (NexDashTable). */
    ns->main_api = api;
    ns->main_backend = api->create(config_str);

    ns->object_api = &NexDashTableAPI;
    ns->object_backend = ns->object_api->create(config_str);

    if (!ns->main_backend || !ns->object_backend) {
        if (ns->main_backend) ns->main_api->destroy(ns->main_backend);
        if (ns->object_backend) ns->object_api->destroy(ns->object_backend);
        free(ns);
        return NULL;
    }

    fprintf(stderr,
            "[NexCache NexStorage] Backend Init:\n"
            "  Main Store (Strings): %s\n"
            "  Object Store (Complex): %s\n"
            "  Narrow-Waist API active.\n",
            ns->main_api->name, ns->object_api->name);
    return ns;
}

void nexstorage_destroy(NexStorage *ns) {
    if (!ns) return;
    if (ns->api && ns->backend) ns->api->destroy(ns->backend);
    if (ns->main_api && ns->main_backend) ns->main_api->destroy(ns->main_backend);
    if (ns->object_api && ns->object_backend) ns->object_api->destroy(ns->object_backend);
    free(ns);
}
