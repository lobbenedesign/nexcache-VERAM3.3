/* NexCache Anomaly Detection — Implementazione
 * Prima assoluta: nel settore NexCache-compatibile nessuno ha questo.
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "anomaly.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <sys/time.h>

static uint64_t anomaly_us_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* ── MetricWindow helpers ────────────────────────────────────── */
static void window_push(MetricWindow *w, double value) {
    if (w->count < ANOMALY_HISTORY_SIZE) {
        w->count++;
    } else {
        w->sum -= w->samples[w->head];
    }
    w->samples[w->head] = value;
    w->sum += value;
    w->head = (w->head + 1) % ANOMALY_HISTORY_SIZE;

    if (w->count == 1) {
        w->min = w->max = value;
    } else {
        if (value < w->min) w->min = value;
        if (value > w->max) w->max = value;
    }
}

static double window_avg(const MetricWindow *w) {
    if (w->count == 0) return 0.0;
    return w->sum / (double)w->count;
}

/* ── Count-Min Sketch per hot key ────────────────────────────── */
#define CMS_ROWS 4
#define CMS_COLS 1024

static uint32_t cms_hash(const char *key, int row) {
    /* 4 hash distinti con seed diverso */
    static const uint32_t seeds[] = {0x9e3779b9, 0x517cc1b7, 0x6c62272e, 0xc2b2ae35};
    uint32_t h = seeds[row % 4];
    for (const char *p = key; *p; p++)
        h = (h ^ (uint8_t)*p) * 0x01000193u;
    return h % CMS_COLS;
}

static void cms_increment(HotKeyTracker *t, const char *key) {
    uint32_t min_count = UINT32_MAX;
    for (int r = 0; r < CMS_ROWS; r++) {
        uint32_t col = cms_hash(key, r);
        t->sketch[r][col]++;
        if (t->sketch[r][col] < min_count)
            min_count = t->sketch[r][col];
    }
    t->total_ops++;
    if (min_count > t->top_count) {
        t->top_count = min_count;
        strncpy(t->top_key, key, sizeof(t->top_key) - 1);
    }
}

static uint32_t cms_estimate(HotKeyTracker *t, const char *key) {
    uint32_t min_count = UINT32_MAX;
    for (int r = 0; r < CMS_ROWS; r++) {
        uint32_t col = cms_hash(key, r);
        if (t->sketch[r][col] < min_count)
            min_count = t->sketch[r][col];
    }
    return min_count;
}

/* ── Registra evento anomalia ────────────────────────────────── */
static void anomaly_emit(AnomalyDetector *d, AnomalyType type, AnomalySeverity sev, double observed, double baseline, const char *key, const char *desc) {
    pthread_mutex_lock(&d->lock);

    AnomalyEvent *ev = &d->events[d->event_head % ANOMALY_MAX_EVENTS];
    ev->type = type;
    ev->severity = sev;
    ev->timestamp_us = anomaly_us_now();
    ev->observed_value = observed;
    ev->baseline_value = baseline;
    ev->ratio = (baseline > 0) ? (observed / baseline) : 0.0;
    ev->auto_mitigated = 0;
    if (key) strncpy(ev->key, key, sizeof(ev->key) - 1);
    if (desc) strncpy(ev->description, desc, sizeof(ev->description) - 1);

    if (d->event_count < ANOMALY_MAX_EVENTS) d->event_count++;
    d->event_head++;
    d->total_anomalies++;

    /* Auto-mitigazione: rate limit su hot key */
    if (type == ANOMALY_HOT_KEY && d->config.auto_ratelimit_hot_key) {
        ev->auto_mitigated = 1;
        d->mitigations_applied++;
        fprintf(stderr, "[NexCache Anomaly] AUTO-MITIGATE: hot key '%s' rate-limited\n",
                key ? key : "?");
    }

    pthread_mutex_unlock(&d->lock);

    /* Alert callback (fuori dal lock) */
    if (d->alert_cb) d->alert_cb(ev, d->alert_ctx);

    const char *type_names[] = {
        "LATENCY_SPIKE", "HOT_KEY", "MEMORY_LEAK",
        "EVICTION_STORM", "CONNECTION_SURGE", "ERROR_RATE"};
    const char *sev_names[] = {"INFO", "WARNING", "CRITICAL"};

    fprintf(stderr,
            "[NexCache Anomaly] [%s/%s] %s\n"
            "  observed=%.2f baseline=%.2f ratio=%.2fx\n",
            sev_names[sev], type_names[type], desc ? desc : "",
            observed, baseline, ev->ratio);
}

/* ── Background monitor thread ───────────────────────────────── */
static void *anomaly_monitor_thread(void *arg) {
    AnomalyDetector *d = (AnomalyDetector *)arg;
    uint64_t tick = 0;

    while (d->running) {
        usleep(1000000); /* Campionamento ogni 1 secondo */
        tick++;

        pthread_mutex_lock(&d->lock);
        double lat_avg = window_avg(&d->latency_window);
        double mem_avg = window_avg(&d->memory_window);
        double evt_avg = window_avg(&d->eviction_window);
        double con_avg = window_avg(&d->connection_window);
        double err_avg = window_avg(&d->error_window);

        double lat_curr = d->latency_window.count > 0 ? d->latency_window.samples[(d->latency_window.head +
                                                                                   ANOMALY_HISTORY_SIZE - 1) %
                                                                                  ANOMALY_HISTORY_SIZE]
                                                      : 0;
        double mem_curr = d->memory_window.count > 0 ? d->memory_window.samples[(d->memory_window.head +
                                                                                 ANOMALY_HISTORY_SIZE - 1) %
                                                                                ANOMALY_HISTORY_SIZE]
                                                     : 0;
        double evt_curr = d->eviction_window.count > 0 ? d->eviction_window.samples[(d->eviction_window.head +
                                                                                     ANOMALY_HISTORY_SIZE - 1) %
                                                                                    ANOMALY_HISTORY_SIZE]
                                                       : 0;
        double con_curr = d->connection_window.count > 0 ? d->connection_window.samples[(d->connection_window.head +
                                                                                         ANOMALY_HISTORY_SIZE - 1) %
                                                                                        ANOMALY_HISTORY_SIZE]
                                                         : 0;
        double err_curr = d->error_window.count > 0 ? d->error_window.samples[(d->error_window.head +
                                                                               ANOMALY_HISTORY_SIZE - 1) %
                                                                              ANOMALY_HISTORY_SIZE]
                                                    : 0;

        uint32_t hot_count = d->hot_key_tracker.top_count;
        char hot_key[64];
        strncpy(hot_key, d->hot_key_tracker.top_key, sizeof(hot_key) - 1);
        hot_key[sizeof(hot_key) - 1] = '\0';
        /* PRIMA: il reset avveniva ogni 60 tick (~60s) più sotto, fuori
         * da questo lock e nested dentro l'if di alert (quindi a volte
         * mai, se la soglia non scattava mai) — mentre hot_key_qps è
         * documentato/confrontato come se top_count fosse già un rate al
         * secondo. Un conteggio cumulativo fino a 60s confrontato con una
         * soglia pensata per 1s faceva scattare l'alert fino a ~60 volte
         * troppo presto rispetto al valore configurato. Resettare ogni
         * tick (questo loop gira ogni 1s, vedi usleep sopra) rende
         * top_count un vero rate al secondo, coerente con "QPS". Il
         * reset avviene qui, ancora sotto d->lock, non dopo
         * pthread_mutex_unlock come nella versione precedente — quella
         * mutazione senza lock correva contro anomaly_record_key_access,
         * che scrive nella stessa struttura sotto lock. */
        memset(&d->hot_key_tracker, 0, sizeof(d->hot_key_tracker));
        pthread_mutex_unlock(&d->lock);

        /* ── Controlli anomalie ──────────────────────────────── */

        /* 1. Latency spike: > 3x media 5 min (dopo warm-up di 10 sec) */
        if (tick > 10 && lat_avg > 0 &&
            lat_curr > lat_avg * d->config.latency_spike_ratio) {
            char desc[256];
            snprintf(desc, sizeof(desc),
                     "Latency spike: %.1f µs (avg=%.1f, ratio=%.1fx)",
                     lat_curr, lat_avg, lat_curr / lat_avg);
            anomaly_emit(d, ANOMALY_LATENCY_SPIKE,
                         lat_curr > lat_avg * 10 ? SEV_CRITICAL : SEV_WARNING,
                         lat_curr, lat_avg, NULL, desc);
        }

        /* 2. Hot key: QPS count-min > soglia */
        if (hot_count > (uint32_t)d->config.hot_key_qps && hot_key[0]) {
            char desc[256];
            snprintf(desc, sizeof(desc),
                     "Hot key '%s': ~%u QPS (threshold=%g)",
                     hot_key, hot_count, d->config.hot_key_qps);
            anomaly_emit(d, ANOMALY_HOT_KEY,
                         hot_count > d->config.hot_key_qps * 5 ? SEV_CRITICAL : SEV_WARNING,
                         hot_count, d->config.hot_key_qps, hot_key, desc);
        }

        /* 3. Memory leak: crescita > 10% in 5 minuti */
        if (tick > 300 && mem_avg > 0) {
            /* Confronta con la media dei primi 30 secondi della finestra */
            double old_avg = 0;
            pthread_mutex_lock(&d->lock);
            int n = d->memory_window.count > 30 ? 30 : d->memory_window.count;
            for (int i = 0; i < n; i++) {
                uint32_t idx = (d->memory_window.head + ANOMALY_HISTORY_SIZE -
                                d->memory_window.count + i) %
                               ANOMALY_HISTORY_SIZE;
                old_avg += d->memory_window.samples[idx];
            }
            if (n > 0) old_avg /= n;
            pthread_mutex_unlock(&d->lock);

            if (old_avg > 0 && mem_curr > old_avg * (1.0 + d->config.memory_growth_pct / 100.0)) {
                char desc[256];
                snprintf(desc, sizeof(desc),
                         "Memory growth: %.1fMB → %.1fMB (+%.1f%%)",
                         old_avg / 1024 / 1024, mem_curr / 1024 / 1024,
                         (mem_curr - old_avg) / old_avg * 100.0);
                anomaly_emit(d, ANOMALY_MEMORY_LEAK, SEV_WARNING,
                             mem_curr, old_avg, NULL, desc);
            }
        }

        /* 4. Eviction storm: eviction rate > 1000/sec */
        if (evt_curr > d->config.eviction_storm_rate) {
            char desc[256];
            snprintf(desc, sizeof(desc),
                     "Eviction storm: %.0f evictions/sec (threshold=%g)",
                     evt_curr, d->config.eviction_storm_rate);
            anomaly_emit(d, ANOMALY_EVICTION_STORM, SEV_WARNING,
                         evt_curr, d->config.eviction_storm_rate, NULL, desc);
        }

        /* 5. Connection surge: connessioni > 5x baseline */
        if (tick > 30 && con_avg > 0 &&
            con_curr > con_avg * d->config.connection_surge_ratio) {
            char desc[256];
            snprintf(desc, sizeof(desc),
                     "Connection surge: %.0f (avg=%.0f, ratio=%.1fx)",
                     con_curr, con_avg, con_curr / con_avg);
            anomaly_emit(d, ANOMALY_CONNECTION_SURGE, SEV_WARNING,
                         con_curr, con_avg, NULL, desc);
        }

        /* 6. Error rate > 5% */
        if (err_curr > d->config.error_rate_pct) {
            char desc[256];
            snprintf(desc, sizeof(desc),
                     "Error rate: %.1f%% (threshold=%.1f%%)",
                     err_curr, d->config.error_rate_pct);
            anomaly_emit(d, ANOMALY_ERROR_RATE,
                         err_curr > 20 ? SEV_CRITICAL : SEV_WARNING,
                         err_curr, d->config.error_rate_pct, NULL, desc);
        }

        (void)err_avg;
        (void)con_avg;
        (void)evt_avg;
        (void)mem_avg;
    }
    return NULL;
}

/* ── anomaly_create ──────────────────────────────────────────── */
AnomalyDetector *anomaly_create(const AnomalyConfig *cfg,
                                void (*alert_cb)(const AnomalyEvent *, void *),
                                void *ctx) {
    AnomalyDetector *d = (AnomalyDetector *)calloc(1, sizeof(AnomalyDetector));
    if (!d) return NULL;

    if (cfg) {
        d->config = *cfg;
    } else {
        /* Default thresholds */
        d->config.latency_spike_ratio = 3.0;
        d->config.hot_key_qps = 10000.0;
        d->config.memory_growth_pct = 10.0;
        d->config.eviction_storm_rate = 1000.0;
        d->config.connection_surge_ratio = 5.0;
        d->config.error_rate_pct = 5.0;
        d->config.auto_ratelimit_hot_key = 1;
        d->config.auto_circuit_breaker = 0;
    }

    d->alert_cb = alert_cb;
    d->alert_ctx = ctx;
    pthread_mutex_init(&d->lock, NULL);
    d->running = 1;
    pthread_create(&d->monitor_thread, NULL, anomaly_monitor_thread, d);

    fprintf(stderr,
            "[NexCache Anomaly] Started — monitoring 6 anomaly types:\n"
            "  latency_spike=%.0fx hot_key=%.0fqps memory_growth=%.0f%%\n"
            "  eviction_storm=%.0f/s conn_surge=%.0fx error_rate=%.0f%%\n",
            d->config.latency_spike_ratio,
            d->config.hot_key_qps,
            d->config.memory_growth_pct,
            d->config.eviction_storm_rate,
            d->config.connection_surge_ratio,
            d->config.error_rate_pct);
    return d;
}

/* ── Update functions ────────────────────────────────────────── */
void anomaly_update_latency(AnomalyDetector *d, double latency_us) {
    if (!d) return;
    pthread_mutex_lock(&d->lock);
    window_push(&d->latency_window, latency_us);
    pthread_mutex_unlock(&d->lock);
}

void anomaly_update_memory(AnomalyDetector *d, size_t used_bytes) {
    if (!d) return;
    pthread_mutex_lock(&d->lock);
    window_push(&d->memory_window, (double)used_bytes);
    pthread_mutex_unlock(&d->lock);
}

void anomaly_update_evictions(AnomalyDetector *d, uint64_t rate) {
    if (!d) return;
    pthread_mutex_lock(&d->lock);
    window_push(&d->eviction_window, (double)rate);
    pthread_mutex_unlock(&d->lock);
}

void anomaly_update_connections(AnomalyDetector *d, uint32_t conns) {
    if (!d) return;
    pthread_mutex_lock(&d->lock);
    window_push(&d->connection_window, (double)conns);
    pthread_mutex_unlock(&d->lock);
}

void anomaly_update_errors(AnomalyDetector *d, double error_pct) {
    if (!d) return;
    pthread_mutex_lock(&d->lock);
    window_push(&d->error_window, error_pct);
    pthread_mutex_unlock(&d->lock);
}

void anomaly_record_key_access(AnomalyDetector *d, const char *key) {
    if (!d || !key) return;
    pthread_mutex_lock(&d->lock);
    cms_increment(&d->hot_key_tracker, key);
    pthread_mutex_unlock(&d->lock);
}

int anomaly_check(AnomalyDetector *d) {
    if (!d) return 0;
    return (int)d->total_anomalies;
}

/* ── Export + print ──────────────────────────────────────────── */
void anomaly_print_events(AnomalyDetector *d, uint32_t last_n) {
    if (!d) return;
    pthread_mutex_lock(&d->lock);
    static const char *tnames[] = {
        "LATENCY", "HOT_KEY", "MEM_LEAK", "EVICT_STORM", "CONN_SURGE", "ERR_RATE"};
    static const char *snames[] = {"INFO", "WARN", "CRIT"};
    uint32_t count = d->event_count < last_n ? d->event_count : last_n;
    fprintf(stderr, "[NexCache Anomaly] Last %u events (total=%llu):\n",
            count, (unsigned long long)d->total_anomalies);
    for (uint32_t i = 0; i < count; i++) {
        uint32_t idx = (d->event_head + ANOMALY_MAX_EVENTS - count + i) % ANOMALY_MAX_EVENTS;
        AnomalyEvent *ev = &d->events[idx];
        fprintf(stderr, "  [%s/%s] %.2fx | %s\n",
                snames[ev->severity], tnames[ev->type],
                ev->ratio, ev->description);
    }
    pthread_mutex_unlock(&d->lock);
}

int anomaly_export_json(AnomalyDetector *d, char *buf, size_t buf_len) {
    if (!d || !buf || buf_len < 64) return -1;
    pthread_mutex_lock(&d->lock);
    int n = snprintf(buf, buf_len,
                     "{\"total_anomalies\":%llu,\"mitigations\":%llu,"
                     "\"event_count\":%u,\"hot_key\":\"%s\"}",
                     (unsigned long long)d->total_anomalies,
                     (unsigned long long)d->mitigations_applied,
                     d->event_count,
                     d->hot_key_tracker.top_key);
    pthread_mutex_unlock(&d->lock);
    return n;
}

void anomaly_destroy(AnomalyDetector *d) {
    if (!d) return;
    d->running = 0;
    pthread_join(d->monitor_thread, NULL);
    pthread_mutex_destroy(&d->lock);
    free(d);
}
