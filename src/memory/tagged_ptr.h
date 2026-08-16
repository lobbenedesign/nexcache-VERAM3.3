/* NexCache Tagged Pointer — MODULO 2 (Aggiornato v6)
 * ============================================================
 * Implementazione sicura rispetto ai Pointer Authentication Code
 * (PAC) su ARM64 server e LA57 / LAM su Intel x86-64.
 * Invece di usare costantemente i bit 48-63 (che collide con PAC
 * o 5-level paging), usa il rilevamento dinamico d'architettura.
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#ifndef NEXCACHE_TAGGED_PTR_H
#define NEXCACHE_TAGGED_PTR_H

#include "arch_probe.h"
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#define TPTR_NULL ((TaggedPtr)0)
#define TPTR_INVALID ((TaggedPtr)UINT64_MAX)

/* ── Tipi oggetto (4 bit = 16 tipi) ────────────────────────── */
typedef enum NexType {
    NEXTYPE_STRING = 0x0,
    NEXTYPE_HASH = 0x1,
    NEXTYPE_LIST = 0x2,
    NEXTYPE_SET = 0x3,
    NEXTYPE_ZSET = 0x4,
    NEXTYPE_VECTOR = 0x5,
    NEXTYPE_JSON = 0x6,
    NEXTYPE_TIMESERIES = 0x7,
    NEXTYPE_STREAM = 0x8,
    NEXTYPE_MODULE = 0x9,
    NEXTYPE_INTERNAL = 0xA,
    NEXTYPE_INVALID = 0xF,
} NexType;

/* ── Sottotipi ──────────────────────────────────────────────── */
typedef enum NexStringSubtype {
    NEXSTR_RAW = 0x0,
    NEXSTR_INT = 0x1,
    NEXSTR_EMBSTR = 0x2,
    NEXSTR_ENCODED = 0x3,
} NexStringSubtype;

typedef enum NexVectorSubtype {
    NEXVEC_FLOAT32 = 0x0,
    NEXVEC_INT8 = 0x1,
    NEXVEC_BINARY = 0x2,
    NEXVEC_FLOAT16 = 0x3,
} NexVectorSubtype;

/* ── Flag ───────────────────────────────────────────────────── */
/* STORIA (2026-08-07): tptr_flags()/tptr_set_flag()/tptr_create()
 * usavano tutti una maschera fissa a 2 bit per il campo flags, ma qui
 * sotto sono dichiarate 4 costanti di flag su 4 bit — TPTR_FLAG_COLD
 * (0x4) e TPTR_FLAG_LOCKED (0x8) erano quindi sempre mascherati via,
 * inutilizzabili su qualunque architettura. Diagnosi: type(4 bit) +
 * subtype(2 bit) + flags(4 bit) = 10 bit servono per rappresentare
 * tutti e 4 i flag, ma non tutte le architetture hanno 10 bit liberi
 * (ARM64 via TBI: 8 bit; x86 con LA57 attivo: 7 bit) — su x86-64 SENZA
 * LA57 (il caso comune, 16 bit liberi) c'è invece ampio margine.
 * FIX: il layout ora si adatta a runtime in base a g_nexarch.metadata_bits,
 * stesso principio già usato da tptr_version/tptr_set_version per la
 * propria degradazione:
 *   - metadata_bits >= 10 → flags a 4 bit (tutti e 4 i flag funzionano),
 *     layout [type:4][subtype:2][flags:4] a partire da NEXPTR_SHIFT.
 *   - metadata_bits < 10  → fallback al layout originale a 2 bit
 *     (solo COMPRESSED/DIRTY rappresentabili; COLD/LOCKED impostati
 *     ma silenziosamente non persistiti, esattamente come la versione
 *     degrada quando metadata_bits < 16). */
#define TPTR_FLAG_COMPRESSED 0x1
#define TPTR_FLAG_DIRTY 0x2
#define TPTR_FLAG_COLD 0x4    /* Richiede metadata_bits >= 10, altrimenti no-op silenzioso */
#define TPTR_FLAG_LOCKED 0x8  /* Richiede metadata_bits >= 10, altrimenti no-op silenzioso */

/* ── Tipo e Accesso ─────────────────────────────────────────── */
typedef uint64_t TaggedPtr;

// Aliases per le macro dipendenti da runtime
#define NEXPTR_SHIFT (g_nexarch.metadata_shift)
#define NEXPTR_ADDRMASK (g_nexarch.addr_mask)
#define NEXPTR_FLAGS_WIDE (g_nexarch.metadata_bits >= 10)

static inline void *tptr_ptr(TaggedPtr tp) {
    return (void *)(tp & NEXPTR_ADDRMASK);
}

static inline uint8_t tptr_flags(TaggedPtr tp) {
    if (NEXPTR_FLAGS_WIDE)
        return (uint8_t)((tp >> NEXPTR_SHIFT) & 0xF);
    return (uint8_t)((tp >> NEXPTR_SHIFT) & 0x3);
}

// Supporto Subtype per compatibilità parziale. In un vero adapt lo si mette nei meta se mancano bit.
// Per compatibilità con macro esistenti, riutilizziamo il "tier" o codifichiamolo qua
static inline uint8_t tptr_subtype(TaggedPtr tp) {
    int fshift = NEXPTR_FLAGS_WIDE ? 4 : 2;
    return (uint8_t)((tp >> (NEXPTR_SHIFT + fshift)) & 0x3);
}

static inline uint8_t tptr_tier(TaggedPtr tp) {
    return tptr_subtype(tp);
}

static inline uint8_t tptr_type(TaggedPtr tp) {
    int tshift = NEXPTR_FLAGS_WIDE ? 6 : 4;
    return (uint8_t)((tp >> (NEXPTR_SHIFT + tshift)) & 0xF);
}

static inline TaggedPtr tptr_create(void *ptr, uint8_t type, uint8_t subtype, uint8_t flags, uint8_t version) {
    uintptr_t raw = (uintptr_t)ptr;
    (void)version; // Ignoriamo la version nel puntatore se abbiamo meno di 16 bit (vedi tptr_set_version)
    if (NEXPTR_FLAGS_WIDE) {
        return (TaggedPtr)raw
             | ((TaggedPtr)(type & 0xF) << (NEXPTR_SHIFT + 6))
             | ((TaggedPtr)(subtype & 0x3) << (NEXPTR_SHIFT + 4))
             | ((TaggedPtr)(flags & 0xF) << (NEXPTR_SHIFT));
    }
    return (TaggedPtr)raw
         | ((TaggedPtr)(type & 0xF) << (NEXPTR_SHIFT + 4))
         | ((TaggedPtr)(subtype & 0x3) << (NEXPTR_SHIFT + 2))
         | ((TaggedPtr)(flags & 0x3) << (NEXPTR_SHIFT));
}

static inline int tptr_has_flag(TaggedPtr tp, uint8_t flag) {
    return (tptr_flags(tp) & flag) != 0;
}

static inline TaggedPtr tptr_set_flag(TaggedPtr tp, uint8_t flag) {
    uint8_t current_flags = tptr_flags(tp);
    current_flags |= flag;
    uint8_t type = tptr_type(tp);
    uint8_t subtype = tptr_subtype(tp);
    return tptr_create(tptr_ptr(tp), type, subtype, current_flags, 0);
}

static inline TaggedPtr tptr_clear_flag(TaggedPtr tp, uint8_t flag) {
    uint8_t current_flags = tptr_flags(tp);
    current_flags &= ~((uint8_t)flag);
    uint8_t type = tptr_type(tp);
    uint8_t subtype = tptr_subtype(tp);
    return tptr_create(tptr_ptr(tp), type, subtype, current_flags, 0);
}

static inline uint8_t tptr_version(TaggedPtr tp) {
    if (g_nexarch.metadata_bits < 16) return 0;
    return (uint8_t)((tp >> (NEXPTR_SHIFT + 12)) & 0xF);
}

static inline TaggedPtr tptr_set_version(TaggedPtr tp, uint8_t v) {
    if (g_nexarch.metadata_bits < 16) return tp;
    tp &= ~((TaggedPtr)0xF << (NEXPTR_SHIFT + 12));
    return tp | ((TaggedPtr)(v & 0xF) << (NEXPTR_SHIFT + 12));
}

static inline TaggedPtr tptr_bump_version(TaggedPtr tp) {
    uint8_t ver = tptr_version(tp);
    ver = (ver + 1) & 0xF;
    return tptr_set_version(tp, ver);
}

static inline int tptr_is_null(TaggedPtr tp) {
    return tptr_ptr(tp) == NULL;
}

static inline int tptr_is_compressed(TaggedPtr tp) {
    return tptr_has_flag(tp, TPTR_FLAG_COMPRESSED);
}

static inline int tptr_is_cold(TaggedPtr tp) {
    return tptr_has_flag(tp, TPTR_FLAG_COLD);
}

static inline int tptr_is_dirty(TaggedPtr tp) {
    return tptr_has_flag(tp, TPTR_FLAG_DIRTY);
}

/* ── Macro di convenienza ───────────────────────────────────── */
#define TPTR_SIMPLE(ptr, type) \
    tptr_create((void *)(ptr), (type), 0, 0, 0)

#define TPTR_VECTOR_F32(ptr) \
    tptr_create((void *)(ptr), NEXTYPE_VECTOR, NEXVEC_FLOAT32, 0, 0)

#define TPTR_VECTOR_INT8(ptr) \
    tptr_create((void *)(ptr), NEXTYPE_VECTOR, NEXVEC_INT8, 0, 0)

#define TPTR_MARK_DIRTY(tp) tptr_set_flag((tp), TPTR_FLAG_DIRTY)
#define TPTR_MARK_COLD(tp) tptr_set_flag((tp), TPTR_FLAG_COLD)
#define TPTR_MARK_COMPRESSED(tp) tptr_set_flag((tp), TPTR_FLAG_COMPRESSED)

static inline const char *tptr_type_name(TaggedPtr tp) {
    switch (tptr_type(tp)) {
    case NEXTYPE_STRING: return "string";
    case NEXTYPE_HASH: return "hash";
    case NEXTYPE_LIST: return "list";
    case NEXTYPE_SET: return "set";
    case NEXTYPE_ZSET: return "zset";
    case NEXTYPE_VECTOR: return "vector";
    case NEXTYPE_JSON: return "json";
    case NEXTYPE_TIMESERIES: return "timeseries";
    case NEXTYPE_STREAM: return "stream";
    case NEXTYPE_MODULE: return "module";
    case NEXTYPE_INTERNAL: return "internal";
    default: return "invalid";
    }
}

#endif /* NEXCACHE_TAGGED_PTR_H */
