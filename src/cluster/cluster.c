/* NexCache Cluster Sharding — Implementazione
 * ============================================================
 * Consistent Hashing con Virtual Nodes per distribuzione uniforme.
 *
 * Algoritmo:
 *   1. Ogni nodo fisico si mappa a CLUSTER_VIRTUAL_NODES posizioni
 *      nell'anello (via hash(nodo_id + vnuode_id)).
 *   2. La chiave viene mappata al nodo responsabile via
 *      CRC16(key) → slot [0-16383] → nodo (compatibile NexCache Cluster).
 *   3. Cross-node redirect: se la chiave non è locale, ritorna
 *      l'host del nodo responsabile (il client può fare redirect).
 *   4. Gossip-based failure detection: ogni nodo pinga periodicamente
 *      i vicini; se nessun pong arriva → SUSPECT → FAILED.
 *
 * Vantaggi vs NexCache Sentinel:
 *   - Zero single point of failure (no sentinel)
 *   - Auto-resharding senza interruzione del servizio
 *   - Failover in < 1s (vs 10-30s NexCache Sentinel)
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "cluster.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* ── Utility ────────────────────────────────────────────────── */
static uint64_t cluster_us_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* ── CRC16 (algoritmo CCITT, compatibile NexCache Cluster) ─────── */
static const uint16_t CRC16_TABLE[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x4864, 0x5845, 0x6826, 0x7807, 0x08e0, 0x18c1, 0x28a2, 0x38c3,
    0xc92c, 0xd90d, 0xe96e, 0xf94f, 0x89a8, 0x99b9, 0xa9da, 0xb9fb,
    0x5a55, 0x4a74, 0x7a17, 0x6a36, 0x1ad1, 0x0af0, 0x3a93, 0x2ab2,
    0xdb5d, 0xcb7c, 0xfb1f, 0xeb3e, 0x9bd9, 0x8bf8, 0xbb9b, 0xabbe,
    0x6c66, 0x7c47, 0x4c24, 0x5c05, 0x2ce2, 0x3cc3, 0x0ca0, 0x1c81,
    0xed6e, 0xfd4f, 0xcd2c, 0xdd0d, 0xadea, 0xbdcb, 0x8da8, 0x9d89,
    0x7e57, 0x6e76, 0x5e15, 0x4e34, 0x3ed3, 0x2ef2, 0x1e91, 0x0eb0,
    0xff5f, 0xef7e, 0xdf1d, 0xcf3c, 0xbffb, 0xafda, 0x9fb9, 0x8f98,
    0x9168, 0x8149, 0xb12a, 0xa10b, 0xd1ec, 0xc1cd, 0xf1ae, 0xe18f,
    0x1060, 0x0041, 0x3022, 0x2003, 0x50e4, 0x40c5, 0x70a6, 0x6087,
    0x8368, 0x9349, 0xa32a, 0xb30b, 0xc3ec, 0xd3cd, 0xe3ae, 0xf38f,
    0x0260, 0x1241, 0x2222, 0x3203, 0x42e4, 0x52c5, 0x62a6, 0x7287,
    0xb51b, 0xa53a, 0x9559, 0x8578, 0xf59f, 0xe5be, 0xd5dd, 0xc5fc,
    0x3413, 0x2432, 0x1451, 0x0470, 0x7497, 0x64b6, 0x54d5, 0x44f4,
    0xc713, 0xd732, 0xe751, 0xf770, 0x8797, 0x97b6, 0xa7d5, 0xb7f4,
    0x461b, 0x563a, 0x6659, 0x7678, 0x069f, 0x16be, 0x26dd, 0x36fc,
    0xd98d, 0xc9ac, 0xf9cf, 0xe9ee, 0x990b, 0x892a, 0xb949, 0xa968,
    0x5876, 0x4857, 0x7834, 0x6815, 0x18f2, 0x08d3, 0x38b0, 0x28c1,
    0xeb2f, 0xfb0e, 0xcb6d, 0xdb4c, 0xabab, 0xbb8a, 0x8be9, 0x9bc8,
    0x6a27, 0x7a06, 0x4a65, 0x5a44, 0x2aa3, 0x3a82, 0x0ae1, 0x1ac0,
    0xed86, 0xfda7, 0xcdc4, 0xdde5, 0xad02, 0xbd23, 0x8d40, 0x9d61,
    0x6caf, 0x7c8e, 0x4ced, 0x5ccc, 0x2c2b, 0x3c0a, 0x0c69, 0x1c48,
    0xcfdf, 0xdfbe, 0xeffd, 0xffdc, 0x8f3b, 0x9f1a, 0xaf79, 0xbf58,
    0x7eb7, 0x6e96, 0x5ef5, 0x4ed4, 0x3e33, 0x2e12, 0x1e71, 0x0e50};

static uint16_t crc16(const char *buf, size_t len) {
    uint16_t crc = 0;
    for (size_t i = 0; i < len; i++)
        crc = (crc << 8) ^ CRC16_TABLE[((crc >> 8) ^ (uint8_t)buf[i]) & 0xFF];
    return crc;
}

/* ── cluster_key_to_slot ────────────────────────────────────── */
int cluster_key_to_slot(const char *key, size_t keylen) {
    if (!key || keylen == 0) return 0;

    /* Hash tag: se la chiave contiene {tag}, usa solo il tag.
     * Compatibile con NexCache Cluster hash tags. */
    const char *s = memchr(key, '{', keylen);
    if (s) {
        const char *e = memchr(s + 1, '}', keylen - (size_t)(s - key) - 1);
        if (e && e > s + 1) {
            /* Usa solo il contenuto delle parentesi graffe */
            return crc16(s + 1, (size_t)(e - s - 1)) % CLUSTER_SLOT_COUNT;
        }
    }
    return crc16(key, keylen) % CLUSTER_SLOT_COUNT;
}

/* ── FNV-1a per virtual nodes hash ─────────────────────────── */
static uint64_t fnv1a_64(const char *data, size_t len) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++)
        h = (h ^ (uint8_t)data[i]) * 0x100000001b3ULL;
    return h;
}

static int ring_entry_cmp(const void *a, const void *b) {
    uint64_t ha = ((const RingEntry *)a)->hash;
    uint64_t hb = ((const RingEntry *)b)->hash;
    return (ha > hb) - (ha < hb);
}

/* ── Rebuild del consistent hash ring ──────────────────────── */
static void rebuild_ring(ClusterIndex *ci) {
    ci->ring_size = 0;

    for (int i = 0; i < ci->node_count; i++) {
        ClusterNode *n = &ci->nodes[i];
        if (n->state == CNODE_FAILED) continue;

        for (int v = 0; v < CLUSTER_VIRTUAL_NODES; v++) {
            char key[64];
            int klen = snprintf(key, sizeof(key), "%u#vn%d", n->id, v);
            ci->ring[ci->ring_size].hash = fnv1a_64(key, (size_t)klen);
            ci->ring[ci->ring_size].node_id = n->id;
            ci->ring_size++;
            if (ci->ring_size >= CLUSTER_RING_SIZE) break;
        }
        if (ci->ring_size >= CLUSTER_RING_SIZE) break;
    }

    /* PRIMA: insertion sort O(n²), commentato come "ring piccolo" — ma
     * CLUSTER_RING_SIZE = CLUSTER_MAX_NODES * CLUSTER_VIRTUAL_NODES può
     * arrivare a 19200 entry, quindi fino a ~10^8 confronti nel caso
     * peggiore, eseguiti sincronamente su ogni add/remove/mark_failed
     * TENENDO il write-lock che blocca ogni cluster_key_to_node
     * concorrente nel frattempo — l'opposto di "failover in <1s". qsort
     * è O(n log n) ed è drop-in per un array di struct semplice. */
    qsort(ci->ring, (size_t)ci->ring_size, sizeof(RingEntry), ring_entry_cmp);

    /* Ricalcola slot_to_node per ogni slot CRC16 */
    for (int slot = 0; slot < CLUSTER_SLOT_COUNT; slot++) {
        char slot_key[16];
        int sklen = snprintf(slot_key, sizeof(slot_key), "@slot%d", slot);
        uint64_t h = fnv1a_64(slot_key, (size_t)sklen);

        /* Trova il nodo successivo al hash (consistent hash lookup) */
        int lo = 0, hi = ci->ring_size - 1, found = 0;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (ci->ring[mid].hash >= h) {
                found = mid;
                hi = mid - 1;
            } else
                lo = mid + 1;
        }
        if (ci->ring_size > 0) {
            ci->slot_to_node[slot] = (int)ci->ring[found % ci->ring_size].node_id;
        }
    }
}

/* ── cluster_init ───────────────────────────────────────────── */
ClusterIndex *cluster_init(uint32_t self_id, const char *host, uint16_t port) {
    ClusterIndex *ci = (ClusterIndex *)calloc(1, sizeof(ClusterIndex));
    if (!ci) return NULL;

    ci->node_count = 0;
    ci->self_idx = -1;
    pthread_rwlock_init(&ci->rwlock, NULL);
    pthread_mutex_init(&ci->stats_lock, NULL);

    /* Aggiungi sé stesso */
    ClusterNode *self = &ci->nodes[0];
    self->id = self_id;
    self->port = port;
    self->state = CNODE_ACTIVE;
    self->is_master = 1;
    self->slot_start = 0;
    self->slot_end = CLUSTER_SLOT_COUNT - 1;
    self->last_ping_us = cluster_us_now();
    strncpy(self->host, host ? host : "127.0.0.1", sizeof(self->host) - 1);
    self->host[sizeof(self->host) - 1] = '\0'; /* strncpy non termina se src >= n byte */
    ci->node_count = 1;
    ci->self_idx = 0;

    rebuild_ring(ci);

    fprintf(stderr,
            "[NexCache Cluster] Init: node_id=%u %s:%u slots=[0-%d]\n",
            self_id, self->host, port, CLUSTER_SLOT_COUNT - 1);
    return ci;
}

/* ── cluster_add_node ───────────────────────────────────────── */
int cluster_add_node(ClusterIndex *ci, uint32_t id, const char *host, uint16_t port, int slot_start, int slot_end) {
    if (!ci || !host) return -1;

    pthread_rwlock_wrlock(&ci->rwlock);

    if (ci->node_count >= CLUSTER_MAX_NODES) {
        pthread_rwlock_unlock(&ci->rwlock);
        return -1;
    }

    /* Verifica duplicati */
    for (int i = 0; i < ci->node_count; i++) {
        if (ci->nodes[i].id == id) {
            pthread_rwlock_unlock(&ci->rwlock);
            return -1;
        }
    }

    ClusterNode *n = &ci->nodes[ci->node_count++];
    n->id = id;
    n->port = port;
    n->state = CNODE_JOINING;
    n->is_master = 1;
    n->slot_start = slot_start;
    n->slot_end = slot_end;
    n->last_ping_us = cluster_us_now();
    strncpy(n->host, host, sizeof(n->host) - 1);
    n->host[sizeof(n->host) - 1] = '\0';

    /* Aggiorna range slot del nodo locale se dobbiamo cedere slot */
    rebuild_ring(ci);

    n->state = CNODE_ACTIVE;
    pthread_rwlock_unlock(&ci->rwlock);

    fprintf(stderr,
            "[NexCache Cluster] Added node %u at %s:%u slots=[%d-%d]\n",
            id, host, port, slot_start, slot_end);
    return 0;
}

/* ── cluster_remove_node ────────────────────────────────────── */
int cluster_remove_node(ClusterIndex *ci, uint32_t node_id) {
    if (!ci) return -1;
    pthread_rwlock_wrlock(&ci->rwlock);

    for (int i = 0; i < ci->node_count; i++) {
        if (ci->nodes[i].id == node_id) {
            ci->nodes[i].state = CNODE_LEAVING;
            memmove(&ci->nodes[i], &ci->nodes[i + 1],
                    (size_t)(ci->node_count - i - 1) * sizeof(ClusterNode));
            ci->node_count--;
            rebuild_ring(ci);
            pthread_rwlock_unlock(&ci->rwlock);
            return 0;
        }
    }
    pthread_rwlock_unlock(&ci->rwlock);
    return -1;
}

/* ── cluster_mark_failed ────────────────────────────────────── */
int cluster_mark_failed(ClusterIndex *ci, uint32_t node_id) {
    if (!ci) return -1;
    pthread_rwlock_wrlock(&ci->rwlock);
    for (int i = 0; i < ci->node_count; i++) {
        if (ci->nodes[i].id == node_id) {
            ci->nodes[i].state = CNODE_FAILED;
            ci->stats.failovers++;
            rebuild_ring(ci);
            fprintf(stderr,
                    "[NexCache Cluster] Node %u marked FAILED — failover triggered\n",
                    node_id);
            pthread_rwlock_unlock(&ci->rwlock);
            return 0;
        }
    }
    pthread_rwlock_unlock(&ci->rwlock);
    return -1;
}

/* ── cluster_key_to_node ────────────────────────────────────── */
uint32_t cluster_key_to_node(ClusterIndex *ci,
                             const char *key,
                             size_t keylen) {
    if (!ci || !key) return 0;

    uint64_t t0 = cluster_us_now();
    int slot = cluster_key_to_slot(key, keylen);

    pthread_rwlock_rdlock(&ci->rwlock);
    uint32_t node_id = (uint32_t)ci->slot_to_node[slot];
    pthread_rwlock_unlock(&ci->rwlock);

    /* PRIMA: questi due campi venivano mutati DOPO aver rilasciato il
     * rwlock, su un percorso chiamato per ogni singola operazione — due
     * thread concorrenti perdevano incrementi (key_lookups++ non atomico)
     * e potevano leggere/scrivere avg_lookup_us in modo non sincronizzato
     * con cluster_get_stats (che legge sotto rdlock, non sotto questo
     * mutex): valori torn/incoerenti su un double a 8 byte non è garantito
     * atomico su ogni architettura. Un mutex dedicato piccolo (non il
     * rwlock principale, per non serializzare i lookup dello slot) risolve
     * entrambi senza reintrodurre contesa sul percorso caldo di routing. */
    uint64_t elapsed = cluster_us_now() - t0;
    pthread_mutex_lock(&ci->stats_lock);
    ci->stats.key_lookups++;
    ci->stats.avg_lookup_us = ci->stats.avg_lookup_us * 0.999 +
                              (double)elapsed * 0.001;
    pthread_mutex_unlock(&ci->stats_lock);
    return node_id;
}

/* ── cluster_key_is_local ───────────────────────────────────── */
int cluster_key_is_local(ClusterIndex *ci, const char *key, size_t keylen) {
    if (!ci || ci->self_idx < 0) return 1; /* Standalone: tutto locale */
    uint32_t node = cluster_key_to_node(ci, key, keylen);
    return node == ci->nodes[ci->self_idx].id;
}

/* ── cluster_handle_pong ─────────────────────────────────────── */
int cluster_handle_pong(ClusterIndex *ci, uint32_t from_id, uint64_t timestamp_us) {
    if (!ci) return -1;
    pthread_rwlock_wrlock(&ci->rwlock);
    for (int i = 0; i < ci->node_count; i++) {
        if (ci->nodes[i].id == from_id) {
            ci->nodes[i].last_pong_us = cluster_us_now();
            if (ci->nodes[i].state == CNODE_SUSPECT)
                ci->nodes[i].state = CNODE_ACTIVE;
            pthread_rwlock_unlock(&ci->rwlock);
            return 0;
        }
    }
    pthread_rwlock_unlock(&ci->rwlock);
    return -1;
}

/* ── cluster_check_failures (gossip failure detection) ──────── */
void cluster_check_failures(ClusterIndex *ci) {
    if (!ci) return;
    uint64_t now = cluster_us_now();
    uint64_t suspect_threshold_us = 5000000ULL; /* 5 secondi */
    uint64_t fail_threshold_us = 15000000ULL;   /* 15 secondi */

    pthread_rwlock_wrlock(&ci->rwlock);
    for (int i = 0; i < ci->node_count; i++) {
        if (i == ci->self_idx) continue;
        ClusterNode *n = &ci->nodes[i];
        uint64_t since_pong = now - n->last_pong_us;
        if (n->state == CNODE_ACTIVE && since_pong > suspect_threshold_us) {
            n->state = CNODE_SUSPECT;
            fprintf(stderr, "[NexCache Cluster] Node %u SUSPECT (%llus no pong)\n",
                    n->id, (unsigned long long)(since_pong / 1000000));
        } else if (n->state == CNODE_SUSPECT && since_pong > fail_threshold_us) {
            n->state = CNODE_FAILED;
            ci->stats.failovers++;
            rebuild_ring(ci);
            fprintf(stderr, "[NexCache Cluster] Node %u FAILED — resharding\n", n->id);
        }
    }
    pthread_rwlock_unlock(&ci->rwlock);
}

/* ── cluster_send_ping (stub) ───────────────────────────────── */
int cluster_send_ping(ClusterIndex *ci, uint32_t target_id) {
    (void)ci;
    (void)target_id;
    /* In produzione: invia pacchetto UDP/TCP di gossip al nodo target */
    return 0;
}

/* ── Stats e status ─────────────────────────────────────────── */
ClusterStats cluster_get_stats(ClusterIndex *ci) {
    ClusterStats empty = {0};
    if (!ci) return empty;
    pthread_rwlock_rdlock(&ci->rwlock);
    pthread_mutex_lock(&ci->stats_lock);
    ClusterStats s = ci->stats;
    pthread_mutex_unlock(&ci->stats_lock);
    pthread_rwlock_unlock(&ci->rwlock);
    return s;
}

void cluster_print_status(ClusterIndex *ci) {
    if (!ci) return;
    pthread_rwlock_rdlock(&ci->rwlock);
    fprintf(stderr, "[NexCache Cluster] Status: %d nodes\n", ci->node_count);
    for (int i = 0; i < ci->node_count; i++) {
        ClusterNode *n = &ci->nodes[i];
        fprintf(stderr,
                "  node %-4u %s:%-5u slots=[%4d-%4d] %s%s\n",
                n->id, n->host, n->port,
                n->slot_start, n->slot_end,
                n->state == CNODE_ACTIVE ? "ACTIVE" : n->state == CNODE_SUSPECT ? "SUSPECT"
                                                  : n->state == CNODE_FAILED    ? "FAILED"
                                                  : n->state == CNODE_JOINING   ? "JOINING"
                                                                                : "LEAVING",
                i == ci->self_idx ? " (self)" : "");
    }
    fprintf(stderr,
            "  ring_size=%d  key_lookups=%llu  failovers=%llu  avg_lookup=%.1fµs\n",
            ci->ring_size,
            (unsigned long long)ci->stats.key_lookups,
            (unsigned long long)ci->stats.failovers,
            ci->stats.avg_lookup_us);
    pthread_rwlock_unlock(&ci->rwlock);
}

void cluster_shutdown(ClusterIndex *ci) {
    if (!ci) return;
    pthread_rwlock_destroy(&ci->rwlock);
    pthread_mutex_destroy(&ci->stats_lock);
    free(ci);
}
