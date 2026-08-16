/* NexTS — TimeSeries Engine (Native BSD)
 * ============================================================
 * Ispirato a Gorilla (Facebook) e NexCacheTimeSeries.
 *
 * Stato attuale (onesto): i campioni sono memorizzati NON compressi
 * (struct NexSample raw, 16 byte/campione). La compressione
 * Delta-of-Delta (timestamp) e XOR (valori double) in stile Gorilla è
 * pianificata ma non ancora implementata — vedi commento in nexts_add()
 * per il motivo. "Auto-tiering su SSD/Cloud" non è implementato.
 * Retention (rimozione automatica dei chunk più vecchi del retention_ms
 * configurato) e aggregazioni (AVG/SUM/MIN/MAX/COUNT) sono implementate.
 * Nessun comando client (TS.ADD/TS.RANGE/...) è collegato a questo
 * modulo — vedi Makefile.
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#ifndef NEXCACHE_NEXTS_H
#define NEXCACHE_NEXTS_H

#include <stdint.h>
#include <stddef.h>

typedef struct NexSample {
    int64_t timestamp;
    double value;
} NexSample;

typedef struct NexTSChunk {
    int64_t start_time;
    int64_t end_time;
    uint32_t count;
    uint32_t size; /* Bytes occupati */
    uint8_t *data; /* Dati compressi */
    struct NexTSChunk *next;
} NexTSChunk;

typedef struct NexTS {
    NexTSChunk *head;
    NexTSChunk *tail;
    uint64_t total_samples;
    int64_t retention_ms;

    /* Last sample per compressione delta-of-delta */
    NexSample last;
    int64_t last_delta;
} NexTS;

/* API */
NexTS *nexts_create(int64_t retention_ms);
void nexts_destroy(NexTS *ts);

/* Returns: 0 su successo, -1 su errore. */
int nexts_add(NexTS *ts, int64_t timestamp, double value);
NexSample *nexts_query(NexTS *ts, int64_t start, int64_t end, uint32_t *count_out);

/* Aggregation */
typedef enum {
    TS_AGG_AVG,
    TS_AGG_SUM,
    TS_AGG_MIN,
    TS_AGG_MAX,
    TS_AGG_COUNT
} NexTSAggType;

double nexts_aggregate(NexTS *ts, int64_t start, int64_t end, NexTSAggType type);

#endif /* NEXCACHE_NEXTS_H */
