/* NexCache Cluster Sharding — Header
 * Consistent Hashing + Virtual Nodes
 * Copyright (c) 2026 NexCache Project — BSD License
 */
#ifndef NEXCACHE_CLUSTER_H
#define NEXCACHE_CLUSTER_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

/* ── Costanti ──────────────────────────────────────────────── */
#define CLUSTER_MAX_NODES 128
#define CLUSTER_VIRTUAL_NODES 150 /* Virtual nodes per nodo fisico */
#define CLUSTER_RING_SIZE (CLUSTER_MAX_NODES * CLUSTER_VIRTUAL_NODES)
#define CLUSTER_SLOT_COUNT 16384 /* Come NexCache Cluster (CRC16 slot) */

/* ── Stato nodo ─────────────────────────────────────────────── */
typedef enum ClusterNodeState {
    CNODE_ACTIVE = 0,
    CNODE_SUSPECT = 1, /* Non risponde, probabile failure */
    CNODE_FAILED = 2,  /* Confermato failure (gossip quorum) */
    CNODE_JOINING = 3, /* In fase di join */
    CNODE_LEAVING = 4, /* In fase di leave (resharding) */
} ClusterNodeState;

/* ── Nodo cluster ───────────────────────────────────────────── */
typedef struct ClusterNode {
    uint32_t id;
    char host[64];
    uint16_t port;
    ClusterNodeState state;
    uint64_t last_ping_us; /* Ultimo heartbeat ricevuto */
    uint64_t last_pong_us;
    int slot_start; /* Slot range [start, end] */
    int slot_end;
    uint64_t keys_count;
    uint64_t bytes_used;
    double ops_per_sec;
    int is_master;       /* 1 = master shard */
    uint32_t replica_of; /* ID del master (se replica) */
} ClusterNode;

/* ── Voce nell'anello consistent hash ──────────────────────── */
typedef struct RingEntry {
    uint64_t hash;    /* Hash virtuale */
    uint32_t node_id; /* Nodo fisico corrispondente */
} RingEntry;

/* ── Statistiche cluster ────────────────────────────────────── */
typedef struct ClusterStats {
    uint64_t key_lookups;          /* Totale lookup shard */
    uint64_t cross_node_redirects; /* Redirect a nodi remoti */
    uint64_t failovers;            /* Failover automatici */
    uint64_t reshards;             /* Resharding completati */
    double avg_lookup_us;
    double distribution_variance; /* Quanto sono bilanciati i nodi */
} ClusterStats;

/* ── Indice cluster ─────────────────────────────────────────── */
typedef struct ClusterIndex {
    ClusterNode nodes[CLUSTER_MAX_NODES];
    int node_count;
    int self_idx;                      /* Indice del nodo locale */
    RingEntry ring[CLUSTER_RING_SIZE]; /* Anello ordinato */
    int ring_size;
    int slot_to_node[CLUSTER_SLOT_COUNT]; /* Mappa diretta */
    ClusterStats stats;
    pthread_rwlock_t rwlock;
    /* Protegge stats.key_lookups/avg_lookup_us, aggiornati fuori dal
     * rwlock principale sul percorso caldo di cluster_key_to_node (per
     * non serializzare ogni lookup di chiave su un wrlock). Un mutex
     * dedicato piccolo, mai tenuto durante il lookup dello slot vero e
     * proprio. */
    pthread_mutex_t stats_lock;
} ClusterIndex;

/* ── API pubblica ───────────────────────────────────────────── */
ClusterIndex *cluster_init(uint32_t self_id, const char *host, uint16_t port);
void cluster_shutdown(ClusterIndex *ci);

int cluster_add_node(ClusterIndex *ci, uint32_t id, const char *host, uint16_t port, int slot_start, int slot_end);
int cluster_remove_node(ClusterIndex *ci, uint32_t node_id);
int cluster_mark_failed(ClusterIndex *ci, uint32_t node_id);

/* Lookup: data una chiave, ritorna il nodo responsabile */
uint32_t cluster_key_to_node(ClusterIndex *ci,
                             const char *key,
                             size_t keylen);
int cluster_key_is_local(ClusterIndex *ci,
                         const char *key,
                         size_t keylen);

/* CRC16 slot (compatibile NexCache Cluster) */
int cluster_key_to_slot(const char *key, size_t keylen);

/* Gossip e health */
int cluster_send_ping(ClusterIndex *ci, uint32_t target_id);
int cluster_handle_pong(ClusterIndex *ci, uint32_t from_id, uint64_t timestamp_us);
void cluster_check_failures(ClusterIndex *ci);

ClusterStats cluster_get_stats(ClusterIndex *ci);
void cluster_print_status(ClusterIndex *ci);

#endif /* NEXCACHE_CLUSTER_H */
