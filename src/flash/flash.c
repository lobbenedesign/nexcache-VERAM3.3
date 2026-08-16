/* NexCache Flash Storage + Anomaly Detection — Implementazioni
 * Flash: Copyright (c) 2026 NexCache Project — BSD License
 */
#include "flash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>


/* ── Heat cooling background thread ─────────────────────────── */
static void *flash_cooling_thread(void *arg) {
    FlashStorage *fs = (FlashStorage *)arg;
    while (fs->running) {
        usleep(fs->config.cooling_interval_ms * 1000);
        pthread_mutex_lock(&fs->lock);
        for (uint32_t i = 0; i < fs->index_count; i++) {
            /* Decrementa heat (cooling esponenziale) */
            if (fs->index[i].heat > 0) {
                fs->index[i].heat--;
                fs->stats.cooling_ops++;
            }
        }
        pthread_mutex_unlock(&fs->lock);
    }
    return NULL;
}

/* ── flash_create ───────────────────────────────────────────── */
FlashStorage *flash_create(const FlashConfig *cfg) {
    if (!cfg) return NULL;

    FlashStorage *fs = (FlashStorage *)calloc(1, sizeof(FlashStorage));
    if (!fs) return NULL;

    fs->config = *cfg;
    if (fs->config.cooling_interval_ms == 0)
        fs->config.cooling_interval_ms = 5000; /* Default 5s */
    if (fs->config.heat_cold_thresh == 0)
        fs->config.heat_cold_thresh = FLASH_HEAT_COLD_THRESH;
    if (fs->config.heat_hot_thresh == 0)
        fs->config.heat_hot_thresh = FLASH_HEAT_HOT_THRESH;

    /* Apri o crea il file FLASH */
    fs->fd = open(cfg->path, O_RDWR | O_CREAT, 0644);
    if (fs->fd < 0) {
        fprintf(stderr, "[NexCache Flash] Cannot open %s: %s\n",
                cfg->path, strerror(errno));
        free(fs);
        return NULL;
    }

    /* Indice in memoria */
    fs->index_cap = 4096;
    fs->index = (FlashIndex *)calloc(fs->index_cap, sizeof(FlashIndex));

    /* Co-access graph */
    fs->co_cap = FLASH_CO_ACCESS_MAX;
    fs->co_graph = (CoAccessEdge *)calloc(fs->co_cap, sizeof(CoAccessEdge));

    pthread_mutex_init(&fs->lock, NULL);
    fs->running = 1;
    pthread_create(&fs->cooling_thread, NULL, flash_cooling_thread, fs);

    fprintf(stderr,
            "[NexCache Flash] Initialized: path=%s max=%zuMB\n"
            "  AI heat scoring: cold_thresh=%d hot_thresh=%d\n"
            "  Co-access prefetch: %s\n",
            cfg->path,
            cfg->max_size_bytes / 1024 / 1024,
            cfg->heat_cold_thresh, cfg->heat_hot_thresh,
            cfg->prefetch_enabled ? "enabled" : "disabled");
    return fs;
}

/* ── flash_write ────────────────────────────────────────────── */
int flash_write(FlashStorage *fs, uint64_t key_hash, const char *key, uint32_t key_len, const uint8_t *value, uint32_t value_len, uint32_t expire_unix) {
    if (!fs || !key || !value) return -1;

    pthread_mutex_lock(&fs->lock);

    /* Check spazio disponibile */
    if (fs->config.max_size_bytes > 0 &&
        fs->write_offset + sizeof(FlashRecord) + key_len + value_len >
            fs->config.max_size_bytes) {
        pthread_mutex_unlock(&fs->lock);
        return -1; /* FLASH pieno */
    }

    /* Scrivi header + key + value */
    FlashRecord hdr = {
        .key_hash = key_hash,
        .key_len = key_len,
        .value_len = value_len,
        .expire_unix = expire_unix,
        .compressed = 0,
    };

    uint64_t offset = fs->write_offset;
    if (pwrite(fs->fd, &hdr, sizeof(hdr), (off_t)offset) < 0 ||
        pwrite(fs->fd, key, key_len, (off_t)(offset + sizeof(hdr))) < 0 ||
        pwrite(fs->fd, value, value_len,
               (off_t)(offset + sizeof(hdr) + key_len)) < 0) {
        pthread_mutex_unlock(&fs->lock);
        return -1;
    }

    uint32_t total_size = (uint32_t)(sizeof(hdr) + key_len + value_len);
    fs->write_offset += total_size;
    fs->file_size += total_size;

    /* Aggiorna indice */
    if (fs->index_count >= fs->index_cap) {
        uint32_t nc = fs->index_cap * 2;
        FlashIndex *ni = (FlashIndex *)realloc(fs->index,
                                               nc * sizeof(FlashIndex));
        if (ni) {
            fs->index = ni;
            fs->index_cap = nc;
        }
    }
    if (fs->index_count < fs->index_cap) {
        FlashIndex *idx = &fs->index[fs->index_count++];
        idx->key_hash = key_hash;
        idx->file_offset = offset;
        idx->record_size = total_size;
        idx->heat = fs->config.heat_cold_thresh; /* Appena spostato */
    }

    fs->stats.writes++;
    fs->stats.bytes_written += value_len;
    fs->stats.evictions++;

    pthread_mutex_unlock(&fs->lock);
    return 0;
}

/* ── flash_read ─────────────────────────────────────────────── */
int flash_read(FlashStorage *fs, uint64_t key_hash, uint8_t *value_buf, uint32_t buf_len, uint32_t *value_len_out) {
    if (!fs || !value_buf || !value_len_out) return -1;

    pthread_mutex_lock(&fs->lock);

    /* Cerca nell'indice */
    for (uint32_t i = 0; i < fs->index_count; i++) {
        if (fs->index[i].key_hash != key_hash) continue;

        FlashRecord hdr;
        if (pread(fs->fd, &hdr, sizeof(hdr),
                  (off_t)fs->index[i].file_offset) < 0) break;

        /* Check expiration */
        if (hdr.expire_unix > 0 && hdr.expire_unix <= (uint32_t)time(NULL)) {
            /* Expired! Remove from index for future reads */
            fs->index[i] = fs->index[--fs->index_count];
            pthread_mutex_unlock(&fs->lock);
            return -1;
        }

        if (hdr.value_len > buf_len) {
            *value_len_out = hdr.value_len;
            pthread_mutex_unlock(&fs->lock);
            return -2; /* Buffer troppo piccolo */
        }

        uint64_t val_off = fs->index[i].file_offset + sizeof(hdr) + hdr.key_len;
        if (pread(fs->fd, value_buf, hdr.value_len, (off_t)val_off) < 0) break;
        *value_len_out = hdr.value_len;

        /* Aumenta heat (promozione candidata) */
        if (fs->index[i].heat < 255) fs->index[i].heat++;

        fs->stats.reads++;
        fs->stats.bytes_read += hdr.value_len;
        pthread_mutex_unlock(&fs->lock);
        return 0;
    }

    fs->stats.reads++;
    pthread_mutex_unlock(&fs->lock);
    return -1;
}

/* ── flash_delete ───────────────────────────────────────────── */
int flash_delete(FlashStorage *fs, uint64_t key_hash) {
    if (!fs) return -1;
    pthread_mutex_lock(&fs->lock);
    for (uint32_t i = 0; i < fs->index_count; i++) {
        if (fs->index[i].key_hash == key_hash) {
            /* Rimuovi dall'indice: swap con ultimo */
            fs->index[i] = fs->index[--fs->index_count];
            pthread_mutex_unlock(&fs->lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&fs->lock);
    return 0;
}

int flash_expire(FlashStorage *fs, uint64_t key_hash, uint32_t expire_unix) {
    if (!fs) return -1;
    pthread_mutex_lock(&fs->lock);
    for (uint32_t i = 0; i < fs->index_count; i++) {
        if (fs->index[i].key_hash == key_hash) {
            /* Aggiorna il record su disco (header in-place) */
            FlashRecord hdr;
            if (pread(fs->fd, &hdr, sizeof(hdr), (off_t)fs->index[i].file_offset) == sizeof(hdr)) {
                hdr.expire_unix = expire_unix;
                if (pwrite(fs->fd, &hdr, sizeof(hdr), (off_t)fs->index[i].file_offset) == sizeof(hdr)) {
                    pthread_mutex_unlock(&fs->lock);
                    return 1;
                }
            }
            break;
        }
    }
    pthread_mutex_unlock(&fs->lock);
    return 0;
}

int64_t flash_ttl(FlashStorage *fs, uint64_t key_hash) {
    if (!fs) return -2;
    pthread_mutex_lock(&fs->lock);
    for (uint32_t i = 0; i < fs->index_count; i++) {
        if (fs->index[i].key_hash == key_hash) {
            FlashRecord hdr;
            if (pread(fs->fd, &hdr, sizeof(hdr), (off_t)fs->index[i].file_offset) == sizeof(hdr)) {
                pthread_mutex_unlock(&fs->lock);
                if (hdr.expire_unix == 0) return -1;
                int64_t ttl_s = (int64_t)hdr.expire_unix - (int64_t)time(NULL);
                return ttl_s > 0 ? ttl_s * 1000 : 0;
            }
            break;
        }
    }
    pthread_mutex_unlock(&fs->lock);
    return -2;
}

void flash_flush(FlashStorage *fs) {
    if (!fs) return;
    pthread_mutex_lock(&fs->lock);
    fs->index_count = 0;
    fs->write_offset = 0;
    fs->file_size = 0;
    if (ftruncate(fs->fd, 0) < 0) {
        /* Ignora errore */
    }
    fs->stats.evictions = 0;
    fs->stats.bytes_written = 0;
    pthread_mutex_unlock(&fs->lock);
}

/* ── Co-access graph: aggiorna probabilità ───────────────────── */
void flash_record_access(FlashStorage *fs, uint64_t key_a, uint64_t key_b) {
    if (!fs || key_a == 0 || key_b == 0 || key_a == key_b) return;
    pthread_mutex_lock(&fs->lock);

    /* Cerca coppia esistente */
    for (uint32_t i = 0; i < fs->co_count; i++) {
        if (fs->co_graph[i].key_hash_a == key_a &&
            fs->co_graph[i].key_hash_b == key_b) {
            fs->co_graph[i].co_access_count++;
            fs->co_graph[i].total_a_count++;
            fs->co_graph[i].probability =
                (float)fs->co_graph[i].co_access_count /
                (float)fs->co_graph[i].total_a_count;
            pthread_mutex_unlock(&fs->lock);
            return;
        }
    }

    /* Nuovo edge */
    if (fs->co_count < fs->co_cap) {
        CoAccessEdge *e = &fs->co_graph[fs->co_count++];
        e->key_hash_a = key_a;
        e->key_hash_b = key_b;
        e->co_access_count = 1;
        e->total_a_count = 1;
        e->probability = 1.0f;
    }

    pthread_mutex_unlock(&fs->lock);
}

/* ── flash_should_promote ───────────────────────────────────── */
/* PRIMA: il loop iterava fino a index_count (dimensione dell'indice item,
 * illimitata, cresce con realloc in flash_write) ma indicizzava co_graph[i]
 * — un array a capacità FISSA (FLASH_CO_ACCESS_MAX = 1024, mai riallocato).
 * Con index_count > 1024 (garantito su un dataset di media dimensione)
 * questo è un heap-buffer-overrun in lettura oltre la fine di co_graph.
 * Concettualmente era anche sbagliato: mescolava l'array degli item su
 * disco (index) con quello del grafo di co-accesso (co_graph) — due
 * strutture semanticamente diverse indicizzate per errore allo stesso
 * modo. La heat di una chiave si legge dal suo FlashIndex, non dal grafo
 * di co-accesso: basta cercare direttamente in fs->index. */
int flash_should_promote(FlashStorage *fs, uint64_t key_hash) {
    if (!fs) return 0;
    pthread_mutex_lock(&fs->lock);
    for (uint32_t i = 0; i < fs->index_count; i++) {
        if (fs->index[i].key_hash == key_hash) {
            int hot = fs->index[i].heat >= fs->config.heat_hot_thresh;
            pthread_mutex_unlock(&fs->lock);
            return hot;
        }
    }
    pthread_mutex_unlock(&fs->lock);
    return 0;
}

/* ── Prefetch predittivo ────────────────────────────────────── */
int flash_prefetch(FlashStorage *fs, uint64_t trigger_hash, void (*load_cb)(uint64_t, const uint8_t *, uint32_t, void *), void *ctx) {
    if (!fs || !fs->config.prefetch_enabled || !load_cb) return 0;

    pthread_mutex_lock(&fs->lock);
    int prefetched = 0;
    for (uint32_t i = 0; i < fs->co_count; i++) {
        CoAccessEdge *e = &fs->co_graph[i];
        if (e->key_hash_a != trigger_hash) continue;
        if (e->probability < 0.70f) continue; /* Solo se P > 70% */

        /* Cerca la key_b nel FLASH e caricala in RAM */
        for (uint32_t j = 0; j < fs->index_count; j++) {
            if (fs->index[j].key_hash != e->key_hash_b) continue;
            FlashRecord hdr;
            if (pread(fs->fd, &hdr, sizeof(hdr),
                      (off_t)fs->index[j].file_offset) < 0) break;
            uint8_t *buf = (uint8_t *)malloc(hdr.value_len);
            if (!buf) break;
            uint64_t voff = fs->index[j].file_offset + sizeof(hdr) + hdr.key_len;
            if (pread(fs->fd, buf, hdr.value_len, (off_t)voff) < 0) {
                free(buf);
                break;
            }
            pthread_mutex_unlock(&fs->lock);
            load_cb(e->key_hash_b, buf, hdr.value_len, ctx);
            free(buf);
            pthread_mutex_lock(&fs->lock);
            fs->stats.prefetches++;
            prefetched++;
            break;
        }
    }
    pthread_mutex_unlock(&fs->lock);
    return prefetched;
}

FlashStats flash_get_stats(FlashStorage *fs) {
    FlashStats empty = {0};
    if (!fs) return empty;
    pthread_mutex_lock(&fs->lock);
    FlashStats s = fs->stats;
    pthread_mutex_unlock(&fs->lock);
    return s;
}

void flash_print_stats(FlashStorage *fs) {
    if (!fs) return;
    FlashStats s = flash_get_stats(fs);
    fprintf(stderr,
            "[NexCache Flash] Stats:\n"
            "  reads:     %llu  writes:     %llu\n"
            "  evictions: %llu  promotions: %llu\n"
            "  prefetch:  %llu  hits:       %llu\n"
            "  bytes_w:   %llu  bytes_r:    %llu\n"
            "  file_size: %zuMB\n",
            (unsigned long long)s.reads, (unsigned long long)s.writes,
            (unsigned long long)s.evictions, (unsigned long long)s.promotions,
            (unsigned long long)s.prefetches, (unsigned long long)s.prefetch_hits,
            (unsigned long long)s.bytes_written, (unsigned long long)s.bytes_read,
            fs->file_size / 1024 / 1024);
}

void flash_destroy(FlashStorage *fs) {
    if (!fs) return;
    fs->running = 0;
    pthread_join(fs->cooling_thread, NULL);
    if (fs->fd >= 0) close(fs->fd);
    pthread_mutex_destroy(&fs->lock);
    free(fs->index);
    free(fs->co_graph);
    free(fs);
}
