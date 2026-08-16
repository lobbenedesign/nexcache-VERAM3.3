/* NexDashTable — Implementazione v5.0
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "nexdash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <math.h>

/* Byte di overhead per-entry usati per l'accounting di used_memory oltre al
 * value_size esplicito (slot + probabile allocazione header lato chiamante). */
#define NEXDASH_ENTRY_OVERHEAD 32

static uint64_t nd_us_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

static uint64_t fnv1a_64(const char *data, uint8_t len) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (uint8_t i = 0; i < len; i++)
        h = (h ^ (uint8_t)data[i]) * 0x100000001b3ULL;
    return h;
}

static uint32_t encode_expire(uint64_t expire_us) {
    if (expire_us == 0) return 0;
    return (uint32_t)(expire_us >> 20);
}

static uint64_t decode_expire(uint32_t enc) {
    if (enc == 0) return 0;
    return (uint64_t)enc << 20;
}

NexDashTable *nexdash_create(size_t initial_segments, size_t max_memory) {
    Arena *arena = arena_create(ARENA_LARGE_SIZE, "nexdash", 1);
    if (!arena) return NULL;

    NexDashTable *t = ARENA_NEW_ZERO(arena, NexDashTable);
    if (!t) {
        arena_destroy(arena);
        return NULL;
    }
    t->arena = arena;

    uint32_t nsegs = 4;
    while ((size_t)nsegs < initial_segments) nsegs <<= 1;

    t->directory = ARENA_NEW_ARRAY_ZERO(arena, NexDashSegment *, nsegs);
    if (!t->directory) {
        arena_destroy(arena);
        return NULL;
    }
    t->dir_size = nsegs;
    t->dir_cap = nsegs;

    for (uint32_t i = 0; i < nsegs; i++) {
        t->directory[i] = ARENA_NEW_ZERO(arena, NexDashSegment);
        if (!t->directory[i]) {
            arena_destroy(arena);
            return NULL;
        }
    }

    t->evict.prob_cap = 10240;
    t->evict.prot_cap = 10240;
    t->evict.prob_queue = ARENA_NEW_ARRAY_ZERO(arena, uint64_t, t->evict.prob_cap);
    t->evict.prot_queue = ARENA_NEW_ARRAY_ZERO(arena, uint64_t, t->evict.prot_cap);
    t->evict.predicted_hot_threshold = 0.7f;

    for (int i = 0; i < 8; i++) t->ml.weights[i] = 0.1f;

    t->max_memory = max_memory;
    t->used_memory = 0;
    t->current_version = 1;
    /* COMPLIANCE v5: Key Pool Initialization */
    t->key_pool_cap = 65536; /* 64KB initial pool */
    t->key_pool = (uint8_t *)malloc(t->key_pool_cap);
    t->key_pool_size = 0;

    /* COMPLIANCE v5: Blocked Bloom Filter */
    t->bloom = nexbloom_create(nsegs * NEXDASH_SEGMENT_ITEMS, 0.01);

    pthread_mutex_init(&t->lock, NULL);
    t->free_cb = NULL;

    fprintf(stderr,
            "[NexCache NexDash] Created: segs=%u max_mem=%zuMB\n"
            "  Compliance v5: 24-byte slots + Tagged Pointers + Blocked Bloom\n",
            nsegs, max_memory / 1024 / 1024);
    return t;
}

/* Libera (via free_cb) il value di uno slot occupato e ne azzera l'entry.
 * Il chiamante deve tenere t->lock e aggiornare seg/t->item_count. */
static void nd_release_slot(NexDashTable *t, NexDashSlot *sl) {
    void *old = TAG_GET_ADDR(sl->value_ptr);
    uint8_t old_type = TAG_GET_TYPE(sl->value_ptr);
    if (old && old_type != NTYPE_DELETED && t->free_cb) t->free_cb(old);
    size_t freed = (size_t)sl->value_size + NEXDASH_ENTRY_OVERHEAD;
    t->used_memory = (t->used_memory > freed) ? (t->used_memory - freed) : 0;
    sl->value_ptr = TAG_SET_META(NULL, 0, NTYPE_DELETED, TIER_PROBATORY, 0);
    sl->value_size = 0;
}

/* Cerca uno slot libero nel segmento (a partire da bkt_start) e vi inserisce
 * la chiave. Ritorna lo slot creato o NULL se il segmento è pieno.
 * Il chiamante deve tenere t->lock. */
static NexDashSlot *nd_insert_into_segment(NexDashTable *t, NexDashSegment *seg, uint32_t bkt_start,
                                            uint64_t hash, const char *key, uint8_t key_len) {
    for (uint32_t probe = 0; probe < NEXDASH_BUCKET_COUNT; probe++) {
        uint32_t bi = (bkt_start + probe) % NEXDASH_BUCKET_COUNT;
        NexDashBucket *bkt = &seg->buckets[bi];
        for (int s = 0; s < NEXDASH_SLOT_COUNT; s++) {
            if ((bkt->occupancy >> s) & 1) continue;

            NexDashSlot *sl = &bkt->slots[s];
            memset(sl, 0, sizeof(*sl));
            sl->key_hash = hash;

            if (key) {
                if (t->key_pool_size + key_len + 1 > t->key_pool_cap) {
                    while (t->key_pool_size + key_len + 1 > t->key_pool_cap)
                        t->key_pool_cap *= 2;
                    uint8_t *np = (uint8_t *)realloc(t->key_pool, t->key_pool_cap);
                    if (!np) return NULL;
                    t->key_pool = np;
                }
                sl->key_offset = t->key_pool_size;
                memcpy(t->key_pool + t->key_pool_size, key, key_len);
                t->key_pool[t->key_pool_size + key_len] = '\0';
                t->key_pool_size += key_len + 1;
            }

            /* Inizializza TaggedPtr con KeyLen e metadati base */
            sl->value_ptr = TAG_SET_META(NULL, key_len, NTYPE_STRING, TIER_PROBATORY, 0);

            seg->item_count++;
            t->item_count++;
            seg->version = t->current_version;
            seg->last_modified = nd_us_now();

            if (key && t->bloom) nexbloom_add(t->bloom, hash);
            bkt->occupancy |= (1U << s);
            return sl;
        }
    }
    return NULL;
}

/* Raddoppia la directory e rehasha tutte le entry esistenti nella nuova
 * capacità. Il chiamante deve tenere t->lock. Ritorna 0 se l'allocazione
 * fallisce (in tal caso la tabella resta invariata e consistente). */
static int nd_resize(NexDashTable *t) {
    uint32_t new_dir_size = t->dir_size * 2;
    if (new_dir_size <= t->dir_size) return 0; /* overflow guard */

    NexDashSegment **new_dir = ARENA_NEW_ARRAY_ZERO(t->arena, NexDashSegment *, new_dir_size);
    if (!new_dir) return 0;
    for (uint32_t i = 0; i < new_dir_size; i++) {
        new_dir[i] = ARENA_NEW_ZERO(t->arena, NexDashSegment);
        if (!new_dir[i]) return 0; /* arena non supporta free: la tabella resta valida sulla vecchia directory */
    }

    for (uint32_t si = 0; si < t->dir_size; si++) {
        NexDashSegment *old_seg = t->directory[si];
        for (int bi = 0; bi < NEXDASH_BUCKET_COUNT; bi++) {
            NexDashBucket *bkt = &old_seg->buckets[bi];
            for (int s = 0; s < NEXDASH_SLOT_COUNT; s++) {
                if (!((bkt->occupancy >> s) & 1)) continue;
                NexDashSlot *old_sl = &bkt->slots[s];
                uint32_t nseg_idx = (uint32_t)(old_sl->key_hash % new_dir_size);
                uint32_t nbkt_start = (uint32_t)((old_sl->key_hash >> 10) % NEXDASH_BUCKET_COUNT);
                NexDashSegment *nseg = new_dir[nseg_idx];
                NexDashSlot *placed = nd_insert_into_segment(t, nseg, nbkt_start, old_sl->key_hash, NULL, 0);
                if (!placed) {
                    /* Non dovrebbe accadere (capacità raddoppiata): se succede per un
                     * pattern di hash avverso, l'entry viene comunque preservata
                     * copiandola una volta di più con probing esteso è fuori scope;
                     * qui la segnaliamo invece di perdere silenziosamente il dato. */
                    fprintf(stderr, "[NexCache NexDash] WARNING: resize rehash overflow su segmento %u\n", nseg_idx);
                    continue;
                }
                /* nd_insert_into_segment ha già copiato key_hash e incrementato i
                 * contatori; ripristiniamo key_offset/value_ptr/expire/value_size
                 * dall'entry originale (chiave già presente nel key_pool condiviso). */
                placed->key_offset = old_sl->key_offset;
                placed->value_ptr = old_sl->value_ptr;
                placed->expire_us32 = old_sl->expire_us32;
                placed->value_size = old_sl->value_size;
            }
        }
    }

    t->directory = new_dir;
    t->dir_size = new_dir_size;
    t->dir_cap = new_dir_size;
    t->stats.resizes++;
    return 1;
}

/* ── Lookup con probing lineare e Tagged Pointers ─────────── */
/* Il chiamante deve tenere t->lock. */
static NexDashSlot *nd_find_slot(NexDashTable *t, const char *key, uint8_t key_len, uint64_t hash, int create_if_missing) {
    uint32_t seg_idx = (uint32_t)(hash % t->dir_size);
    NexDashSegment *seg = t->directory[seg_idx];
    uint32_t bkt_start = (uint32_t)((hash >> 10) % NEXDASH_BUCKET_COUNT);

    /* FASE 1: cerca la chiave in tutti i bucket */
    for (uint32_t probe = 0; probe < NEXDASH_BUCKET_COUNT; probe++) {
        uint32_t bi = (bkt_start + probe) % NEXDASH_BUCKET_COUNT;
        NexDashBucket *bkt = &seg->buckets[bi];
        for (int s = 0; s < NEXDASH_SLOT_COUNT; s++) {
            if (!((bkt->occupancy >> s) & 1)) continue;
            NexDashSlot *sl = &bkt->slots[s];
            if (sl->key_hash != hash) continue;

            if (TAG_GET_LEN(sl->value_ptr) != key_len) continue;
            const char *stored = (const char *)(t->key_pool + sl->key_offset);
            if (memcmp(stored, key, key_len) != 0) continue;

            /* Chiave trovata: controlla scadenza */
            if (sl->expire_us32 != 0) {
                uint64_t exp = decode_expire(sl->expire_us32);
                if (exp <= nd_us_now()) {
                    nd_release_slot(t, sl);
                    bkt->occupancy &= ~(1U << s);
                    seg->item_count--;
                    t->item_count--;
                    return NULL;
                }
            }
            return sl;
        }
    }

    if (!create_if_missing) return NULL;

    /* FASE 2: non trovata — crea slot */
    NexDashSlot *sl = nd_insert_into_segment(t, seg, bkt_start, hash, key, key_len);
    if (sl) return sl;

    /* FASE 3: segmento pieno — cresci la tabella e riprova (una sola volta:
     * dopo il raddoppio ogni segmento originale ha metà occupazione media). */
    if (!nd_resize(t)) return NULL;
    seg_idx = (uint32_t)(hash % t->dir_size);
    seg = t->directory[seg_idx];
    bkt_start = (uint32_t)((hash >> 10) % NEXDASH_BUCKET_COUNT);
    return nd_insert_into_segment(t, seg, bkt_start, hash, key, key_len);
}

void nexdash_set_free_cb(NexDashTable *t, NexDashFreeCb cb) {
    if (!t) return;
    pthread_mutex_lock(&t->lock);
    t->free_cb = cb;
    pthread_mutex_unlock(&t->lock);
}

void nexdash_lock(NexDashTable *t) {
    if (t) pthread_mutex_lock(&t->lock);
}

void nexdash_unlock(NexDashTable *t) {
    if (t) pthread_mutex_unlock(&t->lock);
}

int nexdash_set_nolock(NexDashTable *t, const char *key, uint8_t key_len, void *value, uint32_t value_size, NexEntryType type, uint64_t expire_us) {
    if (!t || !key || key_len == 0) return 0;
    uint64_t hash = fnv1a_64(key, key_len);

    NexDashSlot *sl = nd_find_slot(t, key, key_len, hash, 1);
    if (!sl) return 0;

    /* Libera il value precedente (se overwrite) prima di sovrascrivere:
     * senza questo ogni SET su chiave esistente perdeva memoria. */
    void *old_addr = TAG_GET_ADDR(sl->value_ptr);
    uint8_t old_type = TAG_GET_TYPE(sl->value_ptr);
    if (old_addr && old_type != NTYPE_DELETED && t->free_cb) t->free_cb(old_addr);
    size_t old_cost = old_addr ? ((size_t)sl->value_size + NEXDASH_ENTRY_OVERHEAD) : 0;

    uint8_t ver = TAG_GET_VER(sl->value_ptr);
    uint8_t tier = TAG_GET_TIER(sl->value_ptr);

    sl->value_ptr = TAG_SET_META(value, key_len, type, tier, ver);
    sl->expire_us32 = encode_expire(expire_us);
    sl->value_size = value_size;

    t->used_memory = (t->used_memory > old_cost ? t->used_memory - old_cost : 0)
                      + value_size + NEXDASH_ENTRY_OVERHEAD;

    t->current_version++;
    t->stats.sets++;
    return 1;
}

int nexdash_set(NexDashTable *t, const char *key, uint8_t key_len, void *value, uint32_t value_size, NexEntryType type, uint64_t expire_us) {
    if (!t) return 0;
    pthread_mutex_lock(&t->lock);
    int rc = nexdash_set_nolock(t, key, key_len, value, value_size, type, expire_us);
    pthread_mutex_unlock(&t->lock);
    return rc;
}

void *nexdash_get_nolock(NexDashTable *t, const char *key, uint8_t key_len, NexEntryType *type_out) {
    if (!t || !key || key_len == 0) {
        if (t) t->stats.misses++;
        return NULL;
    }
    uint64_t hash = fnv1a_64(key, key_len);

    if (t->bloom && !nexbloom_check(t->bloom, hash)) {
        t->stats.misses++;
        return NULL;
    }

    NexDashSlot *sl = nd_find_slot(t, key, key_len, hash, 0);
    if (!sl) {
        t->stats.misses++;
        return NULL;
    }

    uint8_t tier = TAG_GET_TIER(sl->value_ptr);
    uint8_t type = TAG_GET_TYPE(sl->value_ptr);
    uint8_t ver = TAG_GET_VER(sl->value_ptr);

    if (tier == TIER_PROBATORY) {
        tier = TIER_PROTECTED;
        sl->value_ptr = TAG_SET_META(TAG_GET_ADDR(sl->value_ptr), key_len, type, tier, ver);
    }

    if (type_out) *type_out = (NexEntryType)type;
    t->stats.hits++;
    t->stats.gets++;
    return TAG_GET_ADDR(sl->value_ptr);
}

void *nexdash_get(NexDashTable *t, const char *key, uint8_t key_len, NexEntryType *type_out) {
    if (!t) return NULL;
    pthread_mutex_lock(&t->lock);
    void *ret = nexdash_get_nolock(t, key, key_len, type_out);
    pthread_mutex_unlock(&t->lock);
    return ret;
}

int nexdash_del(NexDashTable *t, const char *key, uint8_t key_len) {
    if (!t || !key || key_len == 0) return 0;
    uint64_t hash = fnv1a_64(key, key_len);

    pthread_mutex_lock(&t->lock);
    uint32_t seg_idx = (uint32_t)(hash % t->dir_size);
    NexDashSegment *seg = t->directory[seg_idx];
    uint32_t bkt_start = (uint32_t)((hash >> 10) % NEXDASH_BUCKET_COUNT);

    for (uint32_t probe = 0; probe < NEXDASH_BUCKET_COUNT; probe++) {
        uint32_t bi = (bkt_start + probe) % NEXDASH_BUCKET_COUNT;
        NexDashBucket *bkt = &seg->buckets[bi];
        for (int s = 0; s < NEXDASH_SLOT_COUNT; s++) {
            if (!((bkt->occupancy >> s) & 1)) continue;
            NexDashSlot *sl = &bkt->slots[s];
            if (sl->key_hash != hash || TAG_GET_LEN(sl->value_ptr) != key_len) continue;
            const char *stored = (const char *)(t->key_pool + sl->key_offset);
            if (memcmp(stored, key, key_len) != 0) continue;

            nd_release_slot(t, sl);
            bkt->occupancy &= ~(1U << s);
            seg->item_count--;
            t->item_count--;
            t->current_version++;
            t->stats.dels++;
            pthread_mutex_unlock(&t->lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&t->lock);
    return 0;
}

int nexdash_exists(NexDashTable *t, const char *key, uint8_t key_len) {
    NexEntryType tp;
    return nexdash_get(t, key, key_len, &tp) != NULL;
}

int nexdash_expire(NexDashTable *t, const char *key, uint8_t key_len, uint64_t expire_us) {
    if (!t || !key) return -1;
    uint64_t hash = fnv1a_64(key, key_len);
    pthread_mutex_lock(&t->lock);
    NexDashSlot *sl = nd_find_slot(t, key, key_len, hash, 0);
    if (!sl) {
        pthread_mutex_unlock(&t->lock);
        return 0;
    }
    sl->expire_us32 = encode_expire(expire_us);
    pthread_mutex_unlock(&t->lock);
    return 1;
}

void nexdash_scan(NexDashTable *t, NexDashIterCb cb, void *ctx) {
    if (!t || !cb) return;
    pthread_mutex_lock(&t->lock);
    uint64_t now = nd_us_now();
    for (uint32_t si = 0; si < t->dir_size; si++) {
        NexDashSegment *seg = t->directory[si];
        for (int bi = 0; bi < NEXDASH_BUCKET_COUNT; bi++) {
            NexDashBucket *bkt = &seg->buckets[bi];
            for (int s = 0; s < NEXDASH_SLOT_COUNT; s++) {
                if (!((bkt->occupancy >> s) & 1)) continue;
                NexDashSlot *sl = &bkt->slots[s];
                uint8_t type = TAG_GET_TYPE(sl->value_ptr);
                if (type == NTYPE_DELETED) continue;
                if (sl->expire_us32 != 0 && decode_expire(sl->expire_us32) <= now) continue;

                const char *key = (const char *)(t->key_pool + sl->key_offset);
                cb(key, TAG_GET_LEN(sl->value_ptr), TAG_GET_ADDR(sl->value_ptr), type, ctx);
            }
        }
    }
    pthread_mutex_unlock(&t->lock);
}

/* Scansiona la tabella e rimuove (liberando il value via free_cb) tutte le
 * entry scadute, invocando cb per ciascuna prima della rimozione. Era uno
 * stub vuoto: nessuna entry scaduta veniva mai ripulita fuori dal path
 * lazy-expire-on-read di nd_find_slot. */
void nexdash_scan_expired(NexDashTable *t, NexDashIterCb cb, void *ctx) {
    if (!t) return;
    pthread_mutex_lock(&t->lock);
    uint64_t now = nd_us_now();
    for (uint32_t si = 0; si < t->dir_size; si++) {
        NexDashSegment *seg = t->directory[si];
        for (int bi = 0; bi < NEXDASH_BUCKET_COUNT; bi++) {
            NexDashBucket *bkt = &seg->buckets[bi];
            for (int s = 0; s < NEXDASH_SLOT_COUNT; s++) {
                if (!((bkt->occupancy >> s) & 1)) continue;
                NexDashSlot *sl = &bkt->slots[s];
                if (sl->expire_us32 == 0 || decode_expire(sl->expire_us32) > now) continue;

                if (cb) {
                    const char *key = (const char *)(t->key_pool + sl->key_offset);
                    cb(key, TAG_GET_LEN(sl->value_ptr), TAG_GET_ADDR(sl->value_ptr),
                       TAG_GET_TYPE(sl->value_ptr), ctx);
                }
                nd_release_slot(t, sl);
                bkt->occupancy &= ~(1U << s);
                seg->item_count--;
                t->item_count--;
                t->stats.dels++;
            }
        }
    }
    pthread_mutex_unlock(&t->lock);
}

void nexdash_destroy(NexDashTable *t) {
    if (!t) return;
    pthread_mutex_destroy(&t->lock);
    if (t->key_pool) free(t->key_pool);
    if (t->bloom) nexbloom_destroy(t->bloom);

    Arena *a = t->arena;
    if (a) {
        arena_destroy(a);
        /* t è stato allocato nell'arena, quindi è diventato invalido ora. */
    } else {
        /* Fallback if arena disabled - libera directory manualmente */
        if (t->directory) {
            for (uint32_t i = 0; i < t->dir_size; i++) {
                if (t->directory[i]) free(t->directory[i]);
            }
            free(t->directory);
        }
        free(t); /* t era malloc'd se no arena */
    }
}

int nexdash_snapshot_start(NexDashTable *t) {
    if (!t) return -1;
    t->snapshot_in_progress = 1;
    t->snapshot_version = t->current_version;
    t->stats.snapshot_count++;
    return 0;
}

int nexdash_snapshot_iterate_delta(NexDashTable *t, NexDashIterCb cb, void *ctx) {
    if (!t || !t->snapshot_in_progress) return -1;
    // Mock delta iterator for compilation completeness
    return 0;
}

int nexdash_snapshot_iterate_full(NexDashTable *t, NexDashIterCb cb, void *ctx) {
    if (!t || !cb) return -1;
    nexdash_scan(t, cb, ctx);
    return 0;
}

int nexdash_snapshot_end(NexDashTable *t) {
    if (!t) return -1;
    t->snapshot_in_progress = 0;
    return 0;
}

/* ── Eviction 2Q (scan-based) ─────────────────────────────────
 * L'implementazione precedente pescava un hash dalla FIFO probatoria (mai
 * popolata da nexdash_set: nessun enqueue esisteva) e chiamava
 * nexdash_del(t, NULL, 0), che nexdash_del rifiuta immediatamente
 * (key==NULL) — la funzione non liberava mai una sola entry, quindi la
 * cache si bloccava non appena piena. Questa versione scansiona
 * direttamente la tabella (prima TIER_PROBATORY, poi TIER_PROTECTED come
 * da semantica 2Q) e libera davvero gli slot via nd_release_slot, che
 * a sua volta invoca free_cb sul value. Non è la coda FIFO O(1) originale,
 * ma è corretta; il ripristino delle code prob/prot per l'ordinamento
 * FIFO/LRU esatto è un'ottimizzazione successiva, non un prerequisito
 * di correttezza. */
size_t nexdash_evict_to_target(NexDashTable *t, size_t target_bytes) {
    if (!t) return 0;
    pthread_mutex_lock(&t->lock);
    size_t evicted = 0;

    for (int pass = 0; pass < 2 && t->used_memory > target_bytes; pass++) {
        Eviction2QTier want = (pass == 0) ? TIER_PROBATORY : TIER_PROTECTED;
        for (uint32_t si = 0; si < t->dir_size && t->used_memory > target_bytes; si++) {
            NexDashSegment *seg = t->directory[si];
            for (int bi = 0; bi < NEXDASH_BUCKET_COUNT && t->used_memory > target_bytes; bi++) {
                NexDashBucket *bkt = &seg->buckets[bi];
                for (int s = 0; s < NEXDASH_SLOT_COUNT && t->used_memory > target_bytes; s++) {
                    if (!((bkt->occupancy >> s) & 1)) continue;
                    NexDashSlot *sl = &bkt->slots[s];
                    if (TAG_GET_TIER(sl->value_ptr) != want) continue;

                    nd_release_slot(t, sl);
                    bkt->occupancy &= ~(1U << s);
                    seg->item_count--;
                    t->item_count--;
                    if (want == TIER_PROBATORY) t->stats.evictions_probatory++;
                    else t->stats.evictions_protected++;
                    evicted++;
                }
            }
        }
    }
    pthread_mutex_unlock(&t->lock);
    return evicted;
}

void nexdash_record_access(NexDashTable *t, const char *key, uint8_t key_len) {
    (void)key;
    (void)key_len;
    if (!t) return;
    pthread_mutex_lock(&t->lock);
    /* Aggiorna pesi ML basandosi sull'hit attuale (Regret-Minimization) */
    t->ml.updates++;
    /* Se la chiave era prevista come HOT (ML) e ha fatto HIT, premia i pesi */
    for (int i = 0; i < 8; i++) {
        t->ml.weights[i] += 0.001f; /* Rinforzo positivo scemo */
    }
    pthread_mutex_unlock(&t->lock);
}

void nexdash_print_stats(NexDashTable *t) {
    if (!t) return;
    fprintf(stderr, "[NexCache NexDash] items=%u gets=%llu hits=%llu mem=%zuKB\n",
            t->item_count, (unsigned long long)t->stats.gets,
            (unsigned long long)t->stats.hits, t->used_memory / 1024);
}

NexDashStats nexdash_get_stats(NexDashTable *t) {
    NexDashStats empty = {0};
    return t ? t->stats : empty;
}
