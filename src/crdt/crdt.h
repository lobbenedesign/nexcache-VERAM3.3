/* NexCache CRDT (Conflict-free Replicated Data Types) — Header
 * ============================================================
 * Prima assoluta nel mercato: CRDT nativi in un database
 * NexCache-compatibile con Active-Active replication.
 *
 * Tipi implementati:
 *   G-Counter:      solo incrementi, merge = max per nodo
 *   PN-Counter:     incrementi e decrementi, mathematically convergent
 *   OR-Set:         add/remove concorrenti senza conflitti
 *   LWW-Register:   Last-Write-Wins con vector clock
 *
 * Con CRDT qualsiasi nodo può scrivere senza coordinazione e
 * i conflitti vengono risolti MATEMATICAMENTE — zero perdita dati.
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */
#ifndef NEXCACHE_CRDT_H
#define NEXCACHE_CRDT_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#define CRDT_MAX_NODES 128
#define CRDT_MAX_MEMBERS 65536

/* ── Tipi CRDT ──────────────────────────────────────────────── */
typedef enum CRDTType {
    CRDT_G_COUNTER = 0,  /* Grow-only counter */
    CRDT_PN_COUNTER = 1, /* Positive-Negative counter */
    CRDT_OR_SET = 2,     /* Observed-Remove Set */
    CRDT_LWW_REG = 3,    /* Last-Write-Wins Register */
} CRDTType;

/* ── Vector Clock per LWW e OR-Set ─────────────────────────── */
typedef struct VectorClock {
    uint64_t clocks[CRDT_MAX_NODES]; /* Un timestamp per nodo */
    int num_nodes;
} VectorClock;

/* ── G-Counter: un valore per nodo, merge = max ─────────────── */
typedef struct GCounter {
    uint64_t values[CRDT_MAX_NODES]; /* Incrementi per nodo */
    int num_nodes;
    uint32_t self_node;
} GCounter;

/* ── PN-Counter: G-Counter positivo + G-Counter negativo ────── */
typedef struct PNCounter {
    uint64_t positive[CRDT_MAX_NODES]; /* Incrementi */
    uint64_t negative[CRDT_MAX_NODES]; /* Decrementi */
    int num_nodes;
    uint32_t self_node;
} PNCounter;

/* ── OR-Set entry: ogni elemento ha un unique tag per risoluzione */
typedef struct ORSetEntry {
    uint8_t value[256]; /* Valore del membro */
    uint16_t value_len;
    uint64_t add_tag;     /* Unique tag aggiunto all'insert */
    uint32_t origin_node; /* Nodo che ha aggiunto questo elemento */
    int is_removed;       /* 1 = rimosso localmente */
} ORSetEntry;

typedef struct ORSet {
    ORSetEntry *entries;
    uint32_t count;
    uint32_t capacity;
    uint64_t next_tag;
    uint32_t self_node;
    pthread_rwlock_t lock;
} ORSet;

/* ── LWW-Register: stringa con timestamp + node_id per tiebreak */
typedef struct LWWRegister {
    uint8_t value[1024];
    uint16_t value_len;
    uint64_t timestamp_us;
    uint32_t node_id; /* Tiebreak: nodo più alto vince */
    VectorClock vc;
    pthread_mutex_t lock;
} LWWRegister;

/* ── Container generico CRDT ────────────────────────────────── */
typedef struct CRDTObject {
    CRDTType type;
    char key[256];
    union {
        GCounter *g_counter;
        PNCounter *pn_counter;
        ORSet *or_set;
        LWWRegister *lww;
    } data;
} CRDTObject;

/* ── API G-Counter ──────────────────────────────────────────── */
GCounter *gcounter_create(uint32_t self_node_id, int num_nodes);
void gcounter_increment(GCounter *g, uint64_t delta);
uint64_t gcounter_value(const GCounter *g);
void gcounter_merge(GCounter *dst, const GCounter *src);
void gcounter_destroy(GCounter *g);

/* ── API PN-Counter ─────────────────────────────────────────── */
PNCounter *pncounter_create(uint32_t self_node_id, int num_nodes);
void pncounter_increment(PNCounter *p, uint64_t delta);
void pncounter_decrement(PNCounter *p, uint64_t delta);
int64_t pncounter_value(const PNCounter *p);
void pncounter_merge(PNCounter *dst, const PNCounter *src);
void pncounter_destroy(PNCounter *p);

/* ── API OR-Set ─────────────────────────────────────────────── */
ORSet *orset_create(uint32_t self_node_id);
int orset_add(ORSet *s, const uint8_t *value, uint16_t len);
int orset_remove(ORSet *s, const uint8_t *value, uint16_t len);
int orset_contains(ORSet *s, const uint8_t *value, uint16_t len);
uint32_t orset_size(ORSet *s);
void orset_merge(ORSet *dst, const ORSet *src);
void orset_destroy(ORSet *s);

/* Serializzazione a lunghezza variabile per la persistenza in un backend
 * storage flat (es. NexStorage): formato [uint32_t count][uint32_t
 * next_tag][ORSetEntry entries[count]]. Preserva add_tag/origin_node/
 * is_removed esattamente — necessario perché orset_add() genera SEMPRE un
 * nuovo tag con origin_node=self_node, quindi non è utilizzabile per
 * ricostruire un ORSet già esistente senza corrompere la storia dei tag
 * (e con essa la convergenza del merge). */
size_t orset_serialized_size(const ORSet *s);
size_t orset_serialize(ORSet *s, uint8_t *buf, size_t buf_cap);
ORSet *orset_deserialize(const uint8_t *buf, size_t len, uint32_t self_node_id);

/* ── API LWW-Register ─────────────────────────────────────────── */
LWWRegister *lww_create(uint32_t self_node_id, int num_nodes);
int lww_set(LWWRegister *r, const uint8_t *value, uint16_t len);
uint16_t lww_get(const LWWRegister *r, uint8_t *buf, uint16_t buf_len);
void lww_merge(LWWRegister *dst, const LWWRegister *src);
void lww_destroy(LWWRegister *r);

#endif /* NEXCACHE_CRDT_H */
