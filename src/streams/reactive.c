/* NexCache Reactive Streams Backpressure — Implementazione
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "reactive.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>

/* ── Registry globale delle stream BP config ─────────────────── */
#define MAX_BP_STREAMS 256

static StreamBackpressure *g_streams[MAX_BP_STREAMS];
static int g_stream_count = 0;
static pthread_mutex_t g_reg_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Utility tempo ──────────────────────────────────────────── */
static uint64_t bp_us_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* ── Trova stream per nome ──────────────────────────────────── */
static StreamBackpressure *bp_find_nolock(const char *name) {
    for (int i = 0; i < g_stream_count; i++) {
        if (g_streams[i] && strcmp(g_streams[i]->name, name) == 0)
            return g_streams[i];
    }
    return NULL;
}

/* ── stream_bp_init ─────────────────────────────────────────── */
int stream_bp_init(const char *stream_name,
                   BackpressureStrategy strategy,
                   uint64_t max_pending) {
    if (!stream_name || max_pending == 0) return -1;

    pthread_mutex_lock(&g_reg_lock);

    if (bp_find_nolock(stream_name)) {
        pthread_mutex_unlock(&g_reg_lock);
        return -1; /* Già configurato */
    }
    if (g_stream_count >= MAX_BP_STREAMS) {
        pthread_mutex_unlock(&g_reg_lock);
        return -1;
    }

    StreamBackpressure *bp = (StreamBackpressure *)calloc(1, sizeof(StreamBackpressure));
    if (!bp) {
        pthread_mutex_unlock(&g_reg_lock);
        return -1;
    }

    strncpy(bp->name, stream_name, sizeof(bp->name) - 1);
    bp->strategy = strategy;
    bp->max_pending = max_pending;
    bp->current_pending = 0;
    bp->credit_total = max_pending; /* Credito iniziale = capacità max */
    bp->sample_rate = 10;           /* Default: campiona 1/10 */
    bp->sample_counter = 0;
    pthread_mutex_init(&bp->lock, NULL);

    g_streams[g_stream_count++] = bp;
    pthread_mutex_unlock(&g_reg_lock);

    fprintf(stderr,
            "[NexCache Streams] BP stream '%s' init: strategy=%d max_pending=%llu\n",
            stream_name, (int)strategy, (unsigned long long)max_pending);
    return 0;
}

/* ── stream_bp_add ──────────────────────────────────────────── */
int stream_bp_add(const char *stream_name,
                  const char **fields,
                  int nfields,
                  uint32_t timeout_ms,
                  char *out_id,
                  size_t out_id_cap) {
    (void)fields;
    (void)nfields; /* In produzione: passati a XADD */

    pthread_mutex_lock(&g_reg_lock);
    StreamBackpressure *bp = bp_find_nolock(stream_name);
    pthread_mutex_unlock(&g_reg_lock);

    if (!bp) {
        /* Stream non configurato per backpressure: passa direttamente */
        if (out_id) snprintf(out_id, out_id_cap, "*");
        return 0;
    }

    pthread_mutex_lock(&bp->lock);

    int result = 0; /* 0=added, 1=dropped, 2=sampled */

    /* Verifica se c'è credito disponibile */
    if (bp->current_pending >= bp->max_pending) {
        bp->backpressure_ratio = 1.0;

        switch (bp->strategy) {
        case BP_STRATEGY_DROP:
            bp->msgs_dropped++;
            pthread_mutex_unlock(&bp->lock);
            return 1; /* Messaggio droppato */

        case BP_STRATEGY_SAMPLE:
            bp->sample_counter++;
            if ((bp->sample_counter % bp->sample_rate) != 0) {
                bp->msgs_sampled++;
                pthread_mutex_unlock(&bp->lock);
                return 2; /* Campionato (scartato) */
            }
            /* Ogni N-esimo passa */
            break;

        case BP_STRATEGY_EVICT_OLD:
            /* STUB: questo modulo tiene solo un contatore di "pending",
             * non i messaggi stessi (vedi note in reactive.h su
             * stream_bp_read/stream_bp_ack) — non c'è nessuna coda da cui
             * evictare davvero il messaggio più vecchio. Decrementa
             * current_pending per liberare credito e permettere al nuovo
             * messaggio di passare, ma NON evict nulla di reale: se mai
             * integrato con lo stream engine vero (t_stream.c), qui va
             * chiamato l'equivalente di XTRIM sul messaggio più vecchio. */
            if (bp->current_pending > 0) bp->current_pending--;
            break;

        case BP_STRATEGY_BLOCK:
        default: {
            /* PRIMA: quando il while usciva NORMALMENTE (credito tornato
             * disponibile — il caso comune per cui BLOCK esiste), l'ultima
             * azione del corpo del loop era già un pthread_mutex_lock, ma
             * subito dopo il loop il codice rilockava di nuovo
             * incondizionatamente ("pthread_mutex_lock(&bp->lock);" prima
             * di "bp->producer_blocks++") — doppio lock su un mutex non
             * ricorsivo → deadlock del producer ogni volta che il
             * backpressure si risolveva senza timeout. Sul percorso di
             * timeout, invece, `break` usciva dal loop MENTRE il lock era
             * rilasciato (lo unlock è la prima riga del corpo del loop),
             * e gli incrementi di producer_blocks/producer_block_us_total
             * avvenivano quindi senza alcun lock (race). ORA: il lock
             * viene sempre riacquisito esplicitamente prima di uscire dal
             * while (sia per timeout sia normalmente), quindi dopo il
             * while bp->lock è SEMPRE tenuto esattamente una volta, e gli
             * aggiornamenti stats avvengono sempre sotto lock. */
            uint64_t t0 = bp_us_now();
            bool timed_out = false;

            while (bp->current_pending >= bp->max_pending) {
                pthread_mutex_unlock(&bp->lock);

                /* Backoff esponenziale: 1ms → 2ms → 4ms → ... */
                struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000000};
                nanosleep(&ts, NULL);

                if (timeout_ms > 0) {
                    uint64_t elapsed_ms = (bp_us_now() - t0) / 1000;
                    if (elapsed_ms >= timeout_ms) {
                        timed_out = true;
                        pthread_mutex_lock(&bp->lock);
                        break;
                    }
                }
                pthread_mutex_lock(&bp->lock);
            }

            /* bp->lock è tenuto qui in ogni caso. */
            bp->producer_blocks++;
            bp->producer_block_us_total += bp_us_now() - t0;

            if (timed_out) {
                pthread_mutex_unlock(&bp->lock);
                return -1; /* Timeout */
            }
            break;
        }
        }
    }

    /* Produce il messaggio: incrementa pending e decrementa credito */
    bp->current_pending++;
    bp->msgs_produced++;
    if (bp->max_pending > 0)
        bp->backpressure_ratio = (double)bp->current_pending / (double)bp->max_pending;

    /* Genera ID timestamp-based (simile a NexCache stream ID) */
    if (out_id) {
        uint64_t now_ms = bp_us_now() / 1000;
        snprintf(out_id, out_id_cap, "%llu-0", (unsigned long long)now_ms);
    }

    pthread_mutex_unlock(&bp->lock);
    return result;
}

/* ── stream_bp_read ─────────────────────────────────────────── */
int stream_bp_read(const char *stream_name,
                   const char *consumer_group,
                   const char *consumer_name,
                   uint32_t count,
                   void **out_msgs,
                   uint32_t *out_count) {
    (void)consumer_group;
    (void)consumer_name;
    (void)out_msgs;
    /* In produzione: chiama XREADGROUP di NexCache e aggiorna credito */

    pthread_mutex_lock(&g_reg_lock);
    StreamBackpressure *bp = bp_find_nolock(stream_name);
    pthread_mutex_unlock(&g_reg_lock);

    *out_count = 0;
    if (!bp) return -1;

    pthread_mutex_lock(&bp->lock);

    /* Simula la lettura: delivera fino a count messaggi */
    uint32_t available = (uint32_t)(bp->current_pending < count ? bp->current_pending : count);
    *out_count = available;
    bp->msgs_consumed += available;

    pthread_mutex_unlock(&bp->lock);
    return 0;
}

/* ── stream_bp_ack ──────────────────────────────────────────── */
int stream_bp_ack(const char *stream_name,
                  const char *consumer_group,
                  const char **ids,
                  int nids) {
    (void)consumer_group;
    (void)ids;
    if (nids < 0) return -1; /* Evita il wraparound a uint64_t sotto */

    pthread_mutex_lock(&g_reg_lock);
    StreamBackpressure *bp = bp_find_nolock(stream_name);
    pthread_mutex_unlock(&g_reg_lock);
    if (!bp) return -1;

    pthread_mutex_lock(&bp->lock);

    /* Ogni ACK restituisce credito al producer */
    uint64_t to_release = (uint64_t)nids;
    if (to_release > bp->current_pending) to_release = bp->current_pending;
    bp->current_pending -= to_release;
    bp->credit_total += to_release;

    /* Aggiorna ratio */
    if (bp->max_pending > 0)
        bp->backpressure_ratio = (double)bp->current_pending / (double)bp->max_pending;

    pthread_mutex_unlock(&bp->lock);
    return (int)to_release;
}

/* ── stream_bp_get_info ─────────────────────────────────────── */
StreamBackpressure *stream_bp_get_info(const char *stream_name) {
    pthread_mutex_lock(&g_reg_lock);
    StreamBackpressure *bp = bp_find_nolock(stream_name);
    pthread_mutex_unlock(&g_reg_lock);
    return bp;
}

/* ── stream_bp_print_stats ──────────────────────────────────── */
void stream_bp_print_stats(const char *stream_name) {
    pthread_mutex_lock(&g_reg_lock);
    StreamBackpressure *bp = bp_find_nolock(stream_name);
    pthread_mutex_unlock(&g_reg_lock);
    if (!bp) {
        fprintf(stderr, "[NexCache Streams] '%s' not found\n", stream_name);
        return;
    }

    pthread_mutex_lock(&bp->lock);
    fprintf(stderr, "[NexCache Streams] '%s':\n", bp->name);
    fprintf(stderr, "  strategy:     %d\n", (int)bp->strategy);
    fprintf(stderr, "  pending:      %llu / %llu (%.0f%%)\n",
            (unsigned long long)bp->current_pending,
            (unsigned long long)bp->max_pending,
            bp->backpressure_ratio * 100.0);
    fprintf(stderr, "  produced:     %llu\n", (unsigned long long)bp->msgs_produced);
    fprintf(stderr, "  consumed:     %llu\n", (unsigned long long)bp->msgs_consumed);
    fprintf(stderr, "  dropped:      %llu\n", (unsigned long long)bp->msgs_dropped);
    fprintf(stderr, "  sampled:      %llu\n", (unsigned long long)bp->msgs_sampled);
    fprintf(stderr, "  prod_blocks:  %llu (tot_us=%llu)\n",
            (unsigned long long)bp->producer_blocks,
            (unsigned long long)bp->producer_block_us_total);
    pthread_mutex_unlock(&bp->lock);
}

/* ── stream_bp_config ───────────────────────────────────────── */
int stream_bp_config(const char *stream_name,
                     const char *key,
                     const char *value) {
    pthread_mutex_lock(&g_reg_lock);
    StreamBackpressure *bp = bp_find_nolock(stream_name);
    pthread_mutex_unlock(&g_reg_lock);
    if (!bp) return -1;

    pthread_mutex_lock(&bp->lock);

    if (strcmp(key, "max-pending") == 0) {
        bp->max_pending = (uint64_t)atoll(value);
    } else if (strcmp(key, "backpressure-strategy") == 0) {
        if (strcmp(value, "BLOCK") == 0)
            bp->strategy = BP_STRATEGY_BLOCK;
        else if (strcmp(value, "DROP") == 0)
            bp->strategy = BP_STRATEGY_DROP;
        else if (strcmp(value, "SAMPLE") == 0)
            bp->strategy = BP_STRATEGY_SAMPLE;
        else if (strcmp(value, "EVICT_OLD") == 0)
            bp->strategy = BP_STRATEGY_EVICT_OLD;
    } else if (strcmp(key, "sample-rate") == 0) {
        bp->sample_rate = (uint32_t)atoi(value);
        if (bp->sample_rate == 0) bp->sample_rate = 1;
    }

    pthread_mutex_unlock(&bp->lock);
    return 0;
}
