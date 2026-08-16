/* nexts_module — Modulo NexCache che espone il motore timeseries
 * (src/timeseries/nexts.c) ai client via comandi RESP reali.
 *
 * A differenza di nexvector.c, nexts.c NON è nel Makefile del server
 * (confermato: nessun riferimento a timeseries/ in src/Makefile) quindi
 * i suoi simboli non sono esportati dal binario principale via
 * -rdynamic. Questo modulo compila nexts.c direttamente al suo interno
 * (vedi modules/Makefile: nexts_module.so è linkato da nexts_module.xo
 * + nexts.xo) invece di fare affidamento sul dynamic_lookup contro
 * l'eseguibile server.
 *
 * Comandi:
 *   TS.CREATE key [RETENTION ms]
 *   TS.ADD key timestamp value
 *   TS.RANGE key start end
 *   TS.AGGREGATE key start end AVG|SUM|MIN|MAX|COUNT
 *   TS.DEL key   (libera la serie dal registro)
 */
#include "../nexcachemodule.h"
#include "../timeseries/nexts.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define NEXTS_MAX_SERIES 1024
typedef struct {
    char name[64];
    NexTS *ts;
} NexTSEntry;

static NexTSEntry g_series[NEXTS_MAX_SERIES];
static int g_n_series = 0;
static pthread_mutex_t g_registry_lock = PTHREAD_MUTEX_INITIALIZER;

static NexTS *nexts_find_locked(const char *name) {
    for (int i = 0; i < g_n_series; i++) {
        if (strcmp(g_series[i].name, name) == 0) return g_series[i].ts;
    }
    return NULL;
}

static int nexts_copy_name(NexCacheModuleString *arg, char *out, size_t outsz) {
    size_t len;
    const char *p = NexCacheModule_StringPtrLen(arg, &len);
    if (len == 0 || len >= outsz) return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

/* ── TS.CREATE key [RETENTION ms] ─────────────────────────────────────── */
int TSCreate_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc < 2) return NexCacheModule_WrongArity(ctx);

    char name[64];
    if (nexts_copy_name(argv[1], name, sizeof(name)) != 0)
        return NexCacheModule_ReplyWithError(ctx, "ERR nome serie non valido (1-63 char)");

    int64_t retention_ms = 0; /* 0 = nessuna retention */
    for (int i = 2; i < argc; i++) {
        size_t l;
        const char *opt = NexCacheModule_StringPtrLen(argv[i], &l);
        if (!strcasecmp(opt, "RETENTION") && i + 1 < argc) {
            long long r;
            if (NexCacheModule_StringToLongLong(argv[++i], &r) != NEXCACHEMODULE_OK || r < 0)
                return NexCacheModule_ReplyWithError(ctx, "ERR RETENTION deve essere un intero >= 0 (ms)");
            retention_ms = (int64_t)r;
        } else {
            return NexCacheModule_ReplyWithErrorFormat(ctx, "ERR opzione sconosciuta '%s'", opt);
        }
    }

    pthread_mutex_lock(&g_registry_lock);
    if (nexts_find_locked(name) != NULL) {
        pthread_mutex_unlock(&g_registry_lock);
        return NexCacheModule_ReplyWithError(ctx, "ERR serie già esistente");
    }
    if (g_n_series >= NEXTS_MAX_SERIES) {
        pthread_mutex_unlock(&g_registry_lock);
        return NexCacheModule_ReplyWithError(ctx, "ERR limite massimo serie raggiunto");
    }

    NexTS *ts = nexts_create(retention_ms);
    if (!ts) {
        pthread_mutex_unlock(&g_registry_lock);
        return NexCacheModule_ReplyWithError(ctx, "ERR creazione serie fallita");
    }

    strcpy(g_series[g_n_series].name, name);
    g_series[g_n_series].ts = ts;
    g_n_series++;
    pthread_mutex_unlock(&g_registry_lock);

    return NexCacheModule_ReplyWithSimpleString(ctx, "OK");
}

/* ── TS.ADD key timestamp value ───────────────────────────────────────── */
int TSAdd_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc != 4) return NexCacheModule_WrongArity(ctx);

    char name[64];
    if (nexts_copy_name(argv[1], name, sizeof(name)) != 0)
        return NexCacheModule_ReplyWithError(ctx, "ERR nome serie non valido");

    long long ts_val;
    if (NexCacheModule_StringToLongLong(argv[2], &ts_val) != NEXCACHEMODULE_OK)
        return NexCacheModule_ReplyWithError(ctx, "ERR timestamp non valido");

    double value;
    if (NexCacheModule_StringToDouble(argv[3], &value) != NEXCACHEMODULE_OK)
        return NexCacheModule_ReplyWithError(ctx, "ERR value non valido");

    pthread_mutex_lock(&g_registry_lock);
    NexTS *ts = nexts_find_locked(name);
    pthread_mutex_unlock(&g_registry_lock);
    if (!ts) return NexCacheModule_ReplyWithError(ctx, "ERR serie inesistente, usare TS.CREATE prima");

    /* NexTS non ha il proprio lock interno (è pensato per essere usato
     * da un singolo thread scrittore per serie, come Gorilla/Prometheus
     * TSDB) — il registry_lock globale qui sopra protegge solo la
     * lookup, non la scrittura concorrente sulla stessa serie. Per ora
     * accettabile: i comandi client girano nel thread principale del
     * server (nessun path fast-path IO-thread per TS.* in questo fork). */
    int rc = nexts_add(ts, (int64_t)ts_val, value);
    if (rc != 0) return NexCacheModule_ReplyWithError(ctx, "ERR inserimento fallito");
    return NexCacheModule_ReplyWithSimpleString(ctx, "OK");
}

/* ── TS.RANGE key start end ──────────────────────────────────────────── */
int TSRange_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc != 4) return NexCacheModule_WrongArity(ctx);

    char name[64];
    if (nexts_copy_name(argv[1], name, sizeof(name)) != 0)
        return NexCacheModule_ReplyWithError(ctx, "ERR nome serie non valido");

    long long start, end;
    if (NexCacheModule_StringToLongLong(argv[2], &start) != NEXCACHEMODULE_OK ||
        NexCacheModule_StringToLongLong(argv[3], &end) != NEXCACHEMODULE_OK) {
        return NexCacheModule_ReplyWithError(ctx, "ERR start/end non validi");
    }

    pthread_mutex_lock(&g_registry_lock);
    NexTS *ts = nexts_find_locked(name);
    pthread_mutex_unlock(&g_registry_lock);
    if (!ts) return NexCacheModule_ReplyWithError(ctx, "ERR serie inesistente");

    uint32_t count = 0;
    NexSample *samples = nexts_query(ts, (int64_t)start, (int64_t)end, &count);

    NexCacheModule_ReplyWithArray(ctx, count);
    for (uint32_t i = 0; i < count; i++) {
        NexCacheModule_ReplyWithArray(ctx, 2);
        NexCacheModule_ReplyWithLongLong(ctx, (long long)samples[i].timestamp);
        NexCacheModule_ReplyWithDouble(ctx, samples[i].value);
    }
    if (samples) free(samples);
    return NEXCACHEMODULE_OK;
}

/* ── TS.AGGREGATE key start end AVG|SUM|MIN|MAX|COUNT ────────────────── */
int TSAggregate_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc != 5) return NexCacheModule_WrongArity(ctx);

    char name[64];
    if (nexts_copy_name(argv[1], name, sizeof(name)) != 0)
        return NexCacheModule_ReplyWithError(ctx, "ERR nome serie non valido");

    long long start, end;
    if (NexCacheModule_StringToLongLong(argv[2], &start) != NEXCACHEMODULE_OK ||
        NexCacheModule_StringToLongLong(argv[3], &end) != NEXCACHEMODULE_OK) {
        return NexCacheModule_ReplyWithError(ctx, "ERR start/end non validi");
    }

    size_t al;
    const char *aggstr = NexCacheModule_StringPtrLen(argv[4], &al);
    NexTSAggType agg;
    if (!strcasecmp(aggstr, "AVG")) agg = TS_AGG_AVG;
    else if (!strcasecmp(aggstr, "SUM")) agg = TS_AGG_SUM;
    else if (!strcasecmp(aggstr, "MIN")) agg = TS_AGG_MIN;
    else if (!strcasecmp(aggstr, "MAX")) agg = TS_AGG_MAX;
    else if (!strcasecmp(aggstr, "COUNT")) agg = TS_AGG_COUNT;
    else return NexCacheModule_ReplyWithError(ctx, "ERR aggregazione deve essere AVG|SUM|MIN|MAX|COUNT");

    pthread_mutex_lock(&g_registry_lock);
    NexTS *ts = nexts_find_locked(name);
    pthread_mutex_unlock(&g_registry_lock);
    if (!ts) return NexCacheModule_ReplyWithError(ctx, "ERR serie inesistente");

    double result = nexts_aggregate(ts, (int64_t)start, (int64_t)end, agg);
    NexCacheModule_ReplyWithDouble(ctx, result);
    return NEXCACHEMODULE_OK;
}

/* ── TS.DEL key ───────────────────────────────────────────────────────── */
int TSDel_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc != 2) return NexCacheModule_WrongArity(ctx);

    char name[64];
    if (nexts_copy_name(argv[1], name, sizeof(name)) != 0)
        return NexCacheModule_ReplyWithError(ctx, "ERR nome serie non valido");

    pthread_mutex_lock(&g_registry_lock);
    int found = -1;
    for (int i = 0; i < g_n_series; i++) {
        if (strcmp(g_series[i].name, name) == 0) {
            found = i;
            break;
        }
    }
    if (found < 0) {
        pthread_mutex_unlock(&g_registry_lock);
        return NexCacheModule_ReplyWithLongLong(ctx, 0);
    }
    nexts_destroy(g_series[found].ts);
    g_series[found] = g_series[g_n_series - 1];
    g_n_series--;
    pthread_mutex_unlock(&g_registry_lock);

    return NexCacheModule_ReplyWithLongLong(ctx, 1);
}

int NexCacheModule_OnLoad(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    NEXCACHEMODULE_NOT_USED(argv);
    NEXCACHEMODULE_NOT_USED(argc);

    if (NexCacheModule_Init(ctx, "nexts", 1, NEXCACHEMODULE_APIVER_1) == NEXCACHEMODULE_ERR) return NEXCACHEMODULE_ERR;

    if (NexCacheModule_CreateCommand(ctx, "ts.create", TSCreate_NexCacheCommand, "write deny-oom", 0, 0, 0) ==
        NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "ts.add", TSAdd_NexCacheCommand, "write deny-oom", 0, 0, 0) ==
        NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "ts.range", TSRange_NexCacheCommand, "readonly", 0, 0, 0) ==
        NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "ts.aggregate", TSAggregate_NexCacheCommand, "readonly", 0, 0, 0) ==
        NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "ts.del", TSDel_NexCacheCommand, "write", 0, 0, 0) == NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;

    return NEXCACHEMODULE_OK;
}
