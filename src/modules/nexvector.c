/* nexvector — Modulo NexCache che espone l'indice HNSW (src/vector/hnsw.c)
 * ai client via comandi RESP reali. Prima di questo modulo l'HNSW era
 * compilato e linkato nel binario (hnsw_create/hnsw_add/hnsw_search sono
 * simboli reali) ma irraggiungibile: zero comandi client lo richiamavano.
 *
 * Comandi:
 *   VCREATE idx dim [METRIC COSINE|L2|IP] [QUANT F32|I8|BIN] [M m] [EFC efc]
 *   VADD idx ext_id v1 v2 ... vN
 *   VSEARCH idx k v1 v2 ... vN [EF ef]
 *   VDEL idx ext_id
 *   VINFO idx
 *
 * Non tocca commands.def: registrazione via NexCacheModule_CreateCommand,
 * come ogni modulo standard (RediSearch/RedisTimeSeries usano lo stesso
 * meccanismo contro Redis vero).
 */
#include "../nexcachemodule.h"
#include "../vector/hnsw.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* ── Registro indici: nome -> HNSWIndex*, protetto da mutex globale.
 * I comandi girano nel main thread del server per default (nessun
 * MODULE_OPT_ALLOW_NESTED_SIGKEY qui), ma il fast-path IO-thread di questo
 * fork può in teoria invocare comandi concorrentemente in futuro: il lock
 * costa nulla oggi e previene un data race se quel path viene esteso ai
 * moduli domani. */
#define NEXVEC_MAX_INDEXES 256
typedef struct {
    char name[64];
    HNSWIndex *idx;
} NexVecEntry;

static NexVecEntry g_indexes[NEXVEC_MAX_INDEXES];
static int g_n_indexes = 0;
static pthread_mutex_t g_registry_lock = PTHREAD_MUTEX_INITIALIZER;

static HNSWIndex *nexvec_find_locked(const char *name) {
    for (int i = 0; i < g_n_indexes; i++) {
        if (strcmp(g_indexes[i].name, name) == 0) return g_indexes[i].idx;
    }
    return NULL;
}

/* ── VCREATE idx dim [METRIC ...] [QUANT ...] [M m] [EFC efc] ────────── */
int VCreate_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc < 3) return NexCacheModule_WrongArity(ctx);

    size_t namelen;
    const char *name = NexCacheModule_StringPtrLen(argv[1], &namelen);
    if (namelen == 0 || namelen >= sizeof(((NexVecEntry *)0)->name)) {
        return NexCacheModule_ReplyWithError(ctx, "ERR nome indice non valido (1-63 char)");
    }

    long long dim;
    if (NexCacheModule_StringToLongLong(argv[2], &dim) != NEXCACHEMODULE_OK || dim <= 0 || dim > 4096) {
        return NexCacheModule_ReplyWithError(ctx, "ERR dim deve essere un intero 1..4096");
    }

    HNSWMetric metric = HNSW_METRIC_COSINE;
    QuantType quant = HNSW_QUANT_FLOAT32;
    int M = HNSW_DEFAULT_M;
    int efc = HNSW_DEFAULT_EF_CONSTRUCTION;

    for (int i = 3; i < argc; i++) {
        size_t l;
        const char *opt = NexCacheModule_StringPtrLen(argv[i], &l);
        if (!strcasecmp(opt, "METRIC") && i + 1 < argc) {
            size_t vl;
            const char *v = NexCacheModule_StringPtrLen(argv[++i], &vl);
            if (!strcasecmp(v, "COSINE")) metric = HNSW_METRIC_COSINE;
            else if (!strcasecmp(v, "L2")) metric = HNSW_METRIC_L2;
            else if (!strcasecmp(v, "IP")) metric = HNSW_METRIC_IP;
            else return NexCacheModule_ReplyWithError(ctx, "ERR METRIC deve essere COSINE|L2|IP");
        } else if (!strcasecmp(opt, "QUANT") && i + 1 < argc) {
            size_t vl;
            const char *v = NexCacheModule_StringPtrLen(argv[++i], &vl);
            if (!strcasecmp(v, "F32")) quant = HNSW_QUANT_FLOAT32;
            else if (!strcasecmp(v, "I8")) quant = HNSW_QUANT_INT8;
            else if (!strcasecmp(v, "BIN")) quant = HNSW_QUANT_BINARY;
            else return NexCacheModule_ReplyWithError(ctx, "ERR QUANT deve essere F32|I8|BIN");
        } else if (!strcasecmp(opt, "M") && i + 1 < argc) {
            long long mv;
            if (NexCacheModule_StringToLongLong(argv[++i], &mv) != NEXCACHEMODULE_OK || mv <= 0 || mv > 256)
                return NexCacheModule_ReplyWithError(ctx, "ERR M deve essere un intero 1..256");
            M = (int)mv;
        } else if (!strcasecmp(opt, "EFC") && i + 1 < argc) {
            long long ev;
            if (NexCacheModule_StringToLongLong(argv[++i], &ev) != NEXCACHEMODULE_OK || ev <= 0 || ev > 65536)
                return NexCacheModule_ReplyWithError(ctx, "ERR EFC deve essere un intero 1..65536");
            efc = (int)ev;
        } else {
            return NexCacheModule_ReplyWithErrorFormat(ctx, "ERR opzione sconosciuta '%s'", opt);
        }
    }

    char namebuf[64];
    memcpy(namebuf, name, namelen);
    namebuf[namelen] = '\0';

    pthread_mutex_lock(&g_registry_lock);
    if (nexvec_find_locked(namebuf) != NULL) {
        pthread_mutex_unlock(&g_registry_lock);
        return NexCacheModule_ReplyWithError(ctx, "ERR indice già esistente");
    }
    if (g_n_indexes >= NEXVEC_MAX_INDEXES) {
        pthread_mutex_unlock(&g_registry_lock);
        return NexCacheModule_ReplyWithError(ctx, "ERR limite massimo indici raggiunto");
    }

    HNSWIndex *idx = hnsw_create((int)dim, M, efc, metric, quant);
    if (!idx) {
        pthread_mutex_unlock(&g_registry_lock);
        return NexCacheModule_ReplyWithError(ctx, "ERR creazione indice fallita (out of memory?)");
    }

    memcpy(g_indexes[g_n_indexes].name, namebuf, namelen + 1);
    g_indexes[g_n_indexes].idx = idx;
    g_n_indexes++;
    pthread_mutex_unlock(&g_registry_lock);

    return NexCacheModule_ReplyWithSimpleString(ctx, "OK");
}

/* ── VADD idx ext_id v1 v2 ... vN ─────────────────────────────────────── */
int VAdd_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc < 4) return NexCacheModule_WrongArity(ctx);

    size_t namelen;
    const char *name = NexCacheModule_StringPtrLen(argv[1], &namelen);
    char namebuf[64];
    if (namelen >= sizeof(namebuf)) return NexCacheModule_ReplyWithError(ctx, "ERR nome indice non valido");
    memcpy(namebuf, name, namelen);
    namebuf[namelen] = '\0';

    long long ext_id;
    if (NexCacheModule_StringToLongLong(argv[2], &ext_id) != NEXCACHEMODULE_OK || ext_id < 0) {
        return NexCacheModule_ReplyWithError(ctx, "ERR ext_id deve essere un intero >= 0");
    }

    pthread_mutex_lock(&g_registry_lock);
    HNSWIndex *idx = nexvec_find_locked(namebuf);
    pthread_mutex_unlock(&g_registry_lock);
    if (!idx) return NexCacheModule_ReplyWithError(ctx, "ERR indice inesistente, usare VCREATE prima");

    int nvals = argc - 3;
    if (nvals != idx->dim) {
        return NexCacheModule_ReplyWithErrorFormat(ctx, "ERR attesi %d valori per il vettore, ricevuti %d", idx->dim,
                                                    nvals);
    }

    float *vec = (float *)NexCacheModule_Alloc(sizeof(float) * (size_t)nvals);
    for (int i = 0; i < nvals; i++) {
        double d;
        if (NexCacheModule_StringToDouble(argv[3 + i], &d) != NEXCACHEMODULE_OK) {
            NexCacheModule_Free(vec);
            return NexCacheModule_ReplyWithErrorFormat(ctx, "ERR componente %d non è un float valido", i);
        }
        vec[i] = (float)d;
    }

    /* HNSWIndex ha già il proprio rwlock interno (hnsw.c): hnsw_add è
     * safe da chiamare senza lock esterni aggiuntivi qui. */
    int rc = hnsw_add(idx, (hnsw_id_t)ext_id, vec, NULL);
    NexCacheModule_Free(vec);

    if (rc != 0) return NexCacheModule_ReplyWithError(ctx, "ERR inserimento fallito");
    return NexCacheModule_ReplyWithSimpleString(ctx, "OK");
}

/* ── VSEARCH idx k v1 ... vN [EF ef] ─────────────────────────────────── */
int VSearch_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc < 4) return NexCacheModule_WrongArity(ctx);

    size_t namelen;
    const char *name = NexCacheModule_StringPtrLen(argv[1], &namelen);
    char namebuf[64];
    if (namelen >= sizeof(namebuf)) return NexCacheModule_ReplyWithError(ctx, "ERR nome indice non valido");
    memcpy(namebuf, name, namelen);
    namebuf[namelen] = '\0';

    long long k;
    if (NexCacheModule_StringToLongLong(argv[2], &k) != NEXCACHEMODULE_OK || k <= 0 || k > 10000) {
        return NexCacheModule_ReplyWithError(ctx, "ERR k deve essere un intero 1..10000");
    }

    pthread_mutex_lock(&g_registry_lock);
    HNSWIndex *idx = nexvec_find_locked(namebuf);
    pthread_mutex_unlock(&g_registry_lock);
    if (!idx) return NexCacheModule_ReplyWithError(ctx, "ERR indice inesistente");

    /* Argomenti opzionali finali: "EF ef" — individuiamo dove finisce
     * il vettore query controllando se le ultime 2 posizioni sono "EF n". */
    int ef = 0;
    int vec_argc = argc - 3;
    if (vec_argc >= 2) {
        size_t l;
        const char *maybe_ef = NexCacheModule_StringPtrLen(argv[argc - 2], &l);
        if (!strcasecmp(maybe_ef, "EF")) {
            long long efv;
            if (NexCacheModule_StringToLongLong(argv[argc - 1], &efv) != NEXCACHEMODULE_OK || efv <= 0) {
                return NexCacheModule_ReplyWithError(ctx, "ERR EF deve essere un intero positivo");
            }
            ef = (int)efv;
            vec_argc -= 2;
        }
    }

    if (vec_argc != idx->dim) {
        return NexCacheModule_ReplyWithErrorFormat(ctx, "ERR attesi %d valori per il vettore query, ricevuti %d",
                                                    idx->dim, vec_argc);
    }

    float *vec = (float *)NexCacheModule_Alloc(sizeof(float) * (size_t)vec_argc);
    for (int i = 0; i < vec_argc; i++) {
        double d;
        if (NexCacheModule_StringToDouble(argv[3 + i], &d) != NEXCACHEMODULE_OK) {
            NexCacheModule_Free(vec);
            return NexCacheModule_ReplyWithErrorFormat(ctx, "ERR componente %d non è un float valido", i);
        }
        vec[i] = (float)d;
    }

    HNSWResult *results = (HNSWResult *)NexCacheModule_Alloc(sizeof(HNSWResult) * (size_t)k);
    int num_results = 0;
    int rc = hnsw_search(idx, vec, (int)k, ef, results, &num_results);
    NexCacheModule_Free(vec);

    if (rc != 0) {
        NexCacheModule_Free(results);
        return NexCacheModule_ReplyWithError(ctx, "ERR ricerca fallita");
    }

    NexCacheModule_ReplyWithArray(ctx, num_results);
    for (int i = 0; i < num_results; i++) {
        NexCacheModule_ReplyWithArray(ctx, 3);
        NexCacheModule_ReplyWithLongLong(ctx, (long long)results[i].ext_id);
        NexCacheModule_ReplyWithDouble(ctx, (double)results[i].distance);
        NexCacheModule_ReplyWithDouble(ctx, (double)results[i].score);
    }
    NexCacheModule_Free(results);
    return NEXCACHEMODULE_OK;
}

/* ── VDEL idx ext_id ──────────────────────────────────────────────────── */
int VDel_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc != 3) return NexCacheModule_WrongArity(ctx);

    size_t namelen;
    const char *name = NexCacheModule_StringPtrLen(argv[1], &namelen);
    char namebuf[64];
    if (namelen >= sizeof(namebuf)) return NexCacheModule_ReplyWithError(ctx, "ERR nome indice non valido");
    memcpy(namebuf, name, namelen);
    namebuf[namelen] = '\0';

    long long ext_id;
    if (NexCacheModule_StringToLongLong(argv[2], &ext_id) != NEXCACHEMODULE_OK) {
        return NexCacheModule_ReplyWithError(ctx, "ERR ext_id non valido");
    }

    pthread_mutex_lock(&g_registry_lock);
    HNSWIndex *idx = nexvec_find_locked(namebuf);
    pthread_mutex_unlock(&g_registry_lock);
    if (!idx) return NexCacheModule_ReplyWithError(ctx, "ERR indice inesistente");

    int rc = hnsw_delete(idx, (hnsw_id_t)ext_id);
    NexCacheModule_ReplyWithLongLong(ctx, rc == 0 ? 1 : 0);
    return NEXCACHEMODULE_OK;
}

/* ── VINFO idx ────────────────────────────────────────────────────────── */
int VInfo_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc != 2) return NexCacheModule_WrongArity(ctx);

    size_t namelen;
    const char *name = NexCacheModule_StringPtrLen(argv[1], &namelen);
    char namebuf[64];
    if (namelen >= sizeof(namebuf)) return NexCacheModule_ReplyWithError(ctx, "ERR nome indice non valido");
    memcpy(namebuf, name, namelen);
    namebuf[namelen] = '\0';

    pthread_mutex_lock(&g_registry_lock);
    HNSWIndex *idx = nexvec_find_locked(namebuf);
    pthread_mutex_unlock(&g_registry_lock);
    if (!idx) return NexCacheModule_ReplyWithError(ctx, "ERR indice inesistente");

    HNSWStats st = hnsw_get_stats(idx);

    NexCacheModule_ReplyWithArray(ctx, 16);
    NexCacheModule_ReplyWithSimpleString(ctx, "dim");
    NexCacheModule_ReplyWithLongLong(ctx, idx->dim);
    NexCacheModule_ReplyWithSimpleString(ctx, "count");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)st.count);
    NexCacheModule_ReplyWithSimpleString(ctx, "max_layer");
    NexCacheModule_ReplyWithLongLong(ctx, st.max_layer);
    NexCacheModule_ReplyWithSimpleString(ctx, "inserts");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)st.inserts);
    NexCacheModule_ReplyWithSimpleString(ctx, "searches");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)st.searches);
    NexCacheModule_ReplyWithSimpleString(ctx, "deletes");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)st.deletes);
    NexCacheModule_ReplyWithSimpleString(ctx, "avg_search_us");
    NexCacheModule_ReplyWithDouble(ctx, st.avg_search_us);
    NexCacheModule_ReplyWithSimpleString(ctx, "memory_bytes");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)st.memory_bytes);
    return NEXCACHEMODULE_OK;
}

int NexCacheModule_OnLoad(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    NEXCACHEMODULE_NOT_USED(argv);
    NEXCACHEMODULE_NOT_USED(argc);

    if (NexCacheModule_Init(ctx, "nexvector", 1, NEXCACHEMODULE_APIVER_1) == NEXCACHEMODULE_ERR) return NEXCACHEMODULE_ERR;

    if (NexCacheModule_CreateCommand(ctx, "vcreate", VCreate_NexCacheCommand, "write deny-oom", 0, 0, 0) ==
        NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "vadd", VAdd_NexCacheCommand, "write deny-oom", 0, 0, 0) ==
        NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "vsearch", VSearch_NexCacheCommand, "readonly", 0, 0, 0) ==
        NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "vdel", VDel_NexCacheCommand, "write", 0, 0, 0) == NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "vinfo", VInfo_NexCacheCommand, "readonly", 0, 0, 0) == NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;

    return NEXCACHEMODULE_OK;
}
