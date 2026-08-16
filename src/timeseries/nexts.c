#include "nexts.h"
#include <stdlib.h>
#include <string.h>

#define CHUNK_MAX_SAMPLES 128

NexTS *nexts_create(int64_t retention_ms) {
    NexTS *ts = calloc(1, sizeof(NexTS));
    if (!ts) return NULL;
    ts->retention_ms = retention_ms;
    return ts;
}

static NexTSChunk *chunk_create(int64_t start_time) {
    NexTSChunk *c = calloc(1, sizeof(NexTSChunk));
    if (!c) return NULL;
    c->start_time = start_time;
    c->size = CHUNK_MAX_SAMPLES * sizeof(NexSample);
    c->data = malloc(c->size);
    return c;
}

/* Rimuove dalla testa i chunk interamente più vecchi del retention
 * configurato. PRIMA questo era un blocco vuoto (`// ... cleanup logic
 * ...`): nonostante retention_ms fosse un parametro di configurazione
 * accettato da nexts_create, nessun campione veniva mai rimosso — la
 * serie cresceva illimitatamente in memoria indipendentemente da cosa
 * l'utente configurava. Un chunk viene scartato solo se il suo
 * end_time (il timestamp più recente al suo interno) è comunque più
 * vecchio del cutoff, così non si perdono mai campioni ancora dentro
 * la finestra di retention. */
static void nexts_apply_retention(NexTS *ts, int64_t now_ts) {
    if (ts->retention_ms <= 0) return;
    int64_t cutoff = now_ts - ts->retention_ms;

    while (ts->head && ts->head->end_time < cutoff) {
        NexTSChunk *dead = ts->head;
        ts->head = dead->next;
        if (!ts->head) ts->tail = NULL;
        ts->total_samples -= dead->count;
        free(dead->data);
        free(dead);
    }
}

/* NEX-FIX: la convenzione di ritorno era invertita rispetto a TUTTO il
 * resto del codebase (hnsw_add/segcache_set/orset_add ecc. ritornano
 * 0=successo, -1=errore) — questa funzione faceva l'opposto (1=successo,
 * 0=errore). Invisibile finché nessun chiamante reale esisteva (zero
 * comandi client collegati); scoperto scrivendo il modulo TS.* che
 * seguiva la convenzione standard e vedeva "ERR inserimento fallito" ad
 * ogni singolo TS.ADD pur inserendo correttamente i dati (verificato via
 * TS.RANGE). Standardizzato: ora ritorna 0 su successo, -1 su errore. */
int nexts_add(NexTS *ts, int64_t timestamp, double value) {
    if (!ts) return -1;

    nexts_apply_retention(ts, timestamp);

    if (!ts->tail || ts->tail->count >= CHUNK_MAX_SAMPLES) {
        NexTSChunk *new_c = chunk_create(timestamp);
        if (!new_c) return -1;
        if (ts->tail)
            ts->tail->next = new_c;
        else
            ts->head = new_c;
        ts->tail = new_c;
    }

    /* NOTA: i campioni sono memorizzati non compressi (struct NexSample
     * grezza, 16 byte/campione). La compressione Delta-of-Delta (Gorilla,
     * per i timestamp) e XOR (per i valori double) dichiarate nell'header
     * di questo modulo NON sono implementate — una versione precedente di
     * questa funzione calcolava le variabili di delta/XOR e le scartava
     * subito senza scriverle mai in un bitstream, dando l'impressione
     * (falsa) che la compressione fosse attiva. Implementare il bit-packing
     * reale richiede una struttura dati diversa (bitstream variabile per
     * chunk invece di NexSample[] a dimensione fissa) e test di
     * correttezza dedicati che oggi non esistono in questo modulo — non
     * tentato qui per non introdurre un formato dati non verificato. */
    NexSample *samples = (NexSample *)ts->tail->data;
    samples[ts->tail->count].timestamp = timestamp;
    samples[ts->tail->count].value = value;

    ts->tail->count++;
    ts->tail->end_time = timestamp;
    ts->total_samples++;

    ts->last.timestamp = timestamp;
    ts->last.value = value;

    return 0;
}

void nexts_destroy(NexTS *ts) {
    if (!ts) return;
    NexTSChunk *curr = ts->head;
    while (curr) {
        NexTSChunk *next = curr->next;
        free(curr->data);
        free(curr);
        curr = next;
    }
    free(ts);
}

NexSample *nexts_query(NexTS *ts, int64_t start, int64_t end, uint32_t *count_out) {
    if (!ts) return NULL;

    /* Allocazione dinamica per semplicità nello stub */
    uint32_t max_out = (ts->total_samples < 1000) ? (uint32_t)ts->total_samples : 1000;
    NexSample *res = malloc(sizeof(NexSample) * max_out);
    uint32_t found = 0;

    for (NexTSChunk *c = ts->head; c && found < max_out; c = c->next) {
        if (c->end_time < start) continue;
        if (c->start_time > end) break;

        NexSample *samples = (NexSample *)c->data;
        for (uint32_t i = 0; i < c->count && found < max_out; i++) {
            if (samples[i].timestamp >= start && samples[i].timestamp <= end) {
                res[found++] = samples[i];
            }
        }
    }

    *count_out = found;
    return res;
}

/* PRIMA: nexts_aggregate era dichiarata in nexts.h (usata dal tipo
 * NexTSAggType e dal commento "Aggregation" nell'header) ma non era
 * implementata da nessuna parte in questo file — un errore di linker
 * garantito nel momento in cui qualcuno l'avesse effettivamente chiamata.
 * Implementazione diretta sui chunk (senza passare da nexts_query, per
 * evitare l'allocazione/copia intermedia di tutti i campioni). */
double nexts_aggregate(NexTS *ts, int64_t start, int64_t end, NexTSAggType type) {
    if (!ts) return 0.0;

    double sum = 0.0, min = 0.0, max = 0.0;
    uint64_t count = 0;

    for (NexTSChunk *c = ts->head; c; c = c->next) {
        if (c->end_time < start) continue;
        if (c->start_time > end) break;

        NexSample *samples = (NexSample *)c->data;
        for (uint32_t i = 0; i < c->count; i++) {
            int64_t t = samples[i].timestamp;
            if (t < start || t > end) continue;
            double v = samples[i].value;

            if (count == 0) {
                min = max = v;
            } else {
                if (v < min) min = v;
                if (v > max) max = v;
            }
            sum += v;
            count++;
        }
    }

    if (count == 0) return 0.0;

    switch (type) {
        case TS_AGG_SUM:   return sum;
        case TS_AGG_MIN:   return min;
        case TS_AGG_MAX:   return max;
        case TS_AGG_COUNT: return (double)count;
        case TS_AGG_AVG:
        default:
            return sum / (double)count;
    }
}
