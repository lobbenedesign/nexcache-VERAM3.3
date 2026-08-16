/* nexbp_module — Modulo NexCache che espone il motore di backpressure
 * reattivo (src/streams/reactive.c) ai client via comandi RESP reali.
 *
 * Come nexts.c, reactive.c NON è nel Makefile del server principale,
 * quindi viene compilato direttamente in questo modulo (vedi
 * modules/Makefile: nexbp_module.so = nexbp_module.xo + reactive.xo).
 *
 * IMPORTANTE — limite architetturale onesto (documentato in reactive.h):
 * questo modulo gestisce SOLO il credit-accounting del backpressure
 * (quanti messaggi sono "pending", quando bloccare/droppare/campionare
 * il producer). Non possiede i dati dei messaggi e non è integrato con
 * lo stream engine reale (t_stream.c/XADD/XREADGROUP) — XBP.ADD non crea
 * una entry leggibile con XRANGE, e XBP.READ non restituisce payload
 * (out_msgs non è mai popolato in reactive.c, per design attuale). Chi
 * vuole i dati deve usare XADD/XREADGROUP reali IN PARALLELO a questi
 * comandi, usando questi solo per la contabilità del credito. Questo
 * modulo rende quel limite visibile a un client invece di lasciarlo
 * scaffolding morto irraggiungibile.
 *
 * Comandi:
 *   XBP.INIT stream STRATEGY BLOCK|DROP|SAMPLE|EVICT_OLD max_pending
 *   XBP.ADD stream [TIMEOUT ms] field value [field value ...]
 *   XBP.ACK stream group id [id ...]
 *   XBP.INFO stream
 *   XBP.CONFIG stream key value
 */
#include "../nexcachemodule.h"
#include "../streams/reactive.h"
#include <stdlib.h>
#include <string.h>

static int parse_strategy(const char *s, BackpressureStrategy *out) {
    if (!strcasecmp(s, "BLOCK")) { *out = BP_STRATEGY_BLOCK; return 0; }
    if (!strcasecmp(s, "DROP")) { *out = BP_STRATEGY_DROP; return 0; }
    if (!strcasecmp(s, "SAMPLE")) { *out = BP_STRATEGY_SAMPLE; return 0; }
    if (!strcasecmp(s, "EVICT_OLD")) { *out = BP_STRATEGY_EVICT_OLD; return 0; }
    return -1;
}

/* ── XBP.INIT stream STRATEGY <s> max_pending ────────────────────────── */
int XBPInit_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc != 5) return NexCacheModule_WrongArity(ctx);

    size_t sl;
    const char *stream = NexCacheModule_StringPtrLen(argv[1], &sl);
    char streambuf[256];
    if (sl == 0 || sl >= sizeof(streambuf)) return NexCacheModule_ReplyWithError(ctx, "ERR nome stream non valido");
    memcpy(streambuf, stream, sl);
    streambuf[sl] = '\0';

    size_t kl;
    const char *kw = NexCacheModule_StringPtrLen(argv[2], &kl);
    if (strcasecmp(kw, "STRATEGY")) return NexCacheModule_ReplyWithError(ctx, "ERR sintassi: XBP.INIT stream STRATEGY <s> max_pending");

    size_t stl;
    const char *strat = NexCacheModule_StringPtrLen(argv[3], &stl);
    BackpressureStrategy strategy;
    if (parse_strategy(strat, &strategy) != 0)
        return NexCacheModule_ReplyWithError(ctx, "ERR strategy deve essere BLOCK|DROP|SAMPLE|EVICT_OLD");

    long long max_pending;
    if (NexCacheModule_StringToLongLong(argv[4], &max_pending) != NEXCACHEMODULE_OK || max_pending <= 0)
        return NexCacheModule_ReplyWithError(ctx, "ERR max_pending deve essere un intero positivo");

    int rc = stream_bp_init(streambuf, strategy, (uint64_t)max_pending);
    if (rc != 0) return NexCacheModule_ReplyWithError(ctx, "ERR inizializzazione backpressure fallita");
    return NexCacheModule_ReplyWithSimpleString(ctx, "OK");
}

/* ── XBP.ADD stream [TIMEOUT ms] field value [field value ...] ──────── */
int XBPAdd_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc < 4) return NexCacheModule_WrongArity(ctx);

    size_t sl;
    const char *stream = NexCacheModule_StringPtrLen(argv[1], &sl);
    char streambuf[256];
    if (sl == 0 || sl >= sizeof(streambuf)) return NexCacheModule_ReplyWithError(ctx, "ERR nome stream non valido");
    memcpy(streambuf, stream, sl);
    streambuf[sl] = '\0';

    int fields_start = 2;
    uint32_t timeout_ms = 0;
    {
        size_t kl;
        const char *maybe = NexCacheModule_StringPtrLen(argv[2], &kl);
        if (!strcasecmp(maybe, "TIMEOUT") && argc >= 5) {
            long long t;
            if (NexCacheModule_StringToLongLong(argv[3], &t) != NEXCACHEMODULE_OK || t < 0)
                return NexCacheModule_ReplyWithError(ctx, "ERR TIMEOUT deve essere un intero >= 0 (ms)");
            timeout_ms = (uint32_t)t;
            fields_start = 4;
        }
    }

    int nfield_args = argc - fields_start;
    if (nfield_args <= 0 || (nfield_args % 2) != 0)
        return NexCacheModule_ReplyWithError(ctx, "ERR numero dispari di field/value");

    int nfields = nfield_args;
    const char **fields = (const char **)NexCacheModule_Alloc(sizeof(char *) * (size_t)nfields);
    for (int i = 0; i < nfields; i++) {
        size_t l;
        fields[i] = NexCacheModule_StringPtrLen(argv[fields_start + i], &l);
    }

    char out_id[128];
    int rc = stream_bp_add(streambuf, fields, nfields, timeout_ms, out_id, sizeof(out_id));
    NexCacheModule_Free((void *)fields);

    switch (rc) {
        case 0: NexCacheModule_ReplyWithSimpleString(ctx, out_id); break;
        case 1: NexCacheModule_ReplyWithError(ctx, "DROPPED buffer pieno, messaggio scartato (strategia DROP)"); break;
        case 2: NexCacheModule_ReplyWithError(ctx, "SAMPLED messaggio scartato dal campionamento (strategia SAMPLE)"); break;
        default: NexCacheModule_ReplyWithError(ctx, "ERR XBP.ADD fallito (stream non inizializzato con XBP.INIT o backpressure BLOCK con timeout scaduto)"); break;
    }
    return NEXCACHEMODULE_OK;
}

/* ── XBP.ACK stream group id [id ...] ────────────────────────────────── */
int XBPAck_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc < 4) return NexCacheModule_WrongArity(ctx);

    size_t sl;
    const char *stream = NexCacheModule_StringPtrLen(argv[1], &sl);
    char streambuf[256];
    if (sl == 0 || sl >= sizeof(streambuf)) return NexCacheModule_ReplyWithError(ctx, "ERR nome stream non valido");
    memcpy(streambuf, stream, sl);
    streambuf[sl] = '\0';

    size_t gl;
    const char *group = NexCacheModule_StringPtrLen(argv[2], &gl);
    char groupbuf[128];
    if (gl == 0 || gl >= sizeof(groupbuf)) return NexCacheModule_ReplyWithError(ctx, "ERR nome group non valido");
    memcpy(groupbuf, group, gl);
    groupbuf[gl] = '\0';

    int nids = argc - 3;
    const char **ids = (const char **)NexCacheModule_Alloc(sizeof(char *) * (size_t)nids);
    for (int i = 0; i < nids; i++) {
        size_t l;
        ids[i] = NexCacheModule_StringPtrLen(argv[3 + i], &l);
    }

    int rc = stream_bp_ack(streambuf, groupbuf, ids, nids);
    NexCacheModule_Free((void *)ids);

    if (rc < 0) return NexCacheModule_ReplyWithError(ctx, "ERR XBP.ACK fallito");
    return NexCacheModule_ReplyWithLongLong(ctx, rc);
}

/* ── XBP.INFO stream ──────────────────────────────────────────────────── */
int XBPInfo_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc != 2) return NexCacheModule_WrongArity(ctx);

    size_t sl;
    const char *stream = NexCacheModule_StringPtrLen(argv[1], &sl);
    char streambuf[256];
    if (sl == 0 || sl >= sizeof(streambuf)) return NexCacheModule_ReplyWithError(ctx, "ERR nome stream non valido");
    memcpy(streambuf, stream, sl);
    streambuf[sl] = '\0';

    StreamBackpressure *bp = stream_bp_get_info(streambuf);
    if (!bp) return NexCacheModule_ReplyWithError(ctx, "ERR stream non inizializzato con XBP.INIT");

    NexCacheModule_ReplyWithArray(ctx, 20);
    NexCacheModule_ReplyWithSimpleString(ctx, "max_pending");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)bp->max_pending);
    NexCacheModule_ReplyWithSimpleString(ctx, "current_pending");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)bp->current_pending);
    NexCacheModule_ReplyWithSimpleString(ctx, "msgs_produced");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)bp->msgs_produced);
    NexCacheModule_ReplyWithSimpleString(ctx, "msgs_dropped");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)bp->msgs_dropped);
    NexCacheModule_ReplyWithSimpleString(ctx, "msgs_sampled");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)bp->msgs_sampled);
    NexCacheModule_ReplyWithSimpleString(ctx, "producer_blocks");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)bp->producer_blocks);
    NexCacheModule_ReplyWithSimpleString(ctx, "avg_producer_block_us");
    NexCacheModule_ReplyWithDouble(ctx, bp->avg_producer_block_us);
    NexCacheModule_ReplyWithSimpleString(ctx, "backpressure_ratio");
    NexCacheModule_ReplyWithDouble(ctx, bp->backpressure_ratio);
    NexCacheModule_ReplyWithSimpleString(ctx, "credit_total");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)bp->credit_total);
    NexCacheModule_ReplyWithSimpleString(ctx, "strategy");
    NexCacheModule_ReplyWithLongLong(ctx, (long long)bp->strategy);
    return NEXCACHEMODULE_OK;
}

/* ── XBP.CONFIG stream key value ─────────────────────────────────────── */
int XBPConfig_NexCacheCommand(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    if (argc != 4) return NexCacheModule_WrongArity(ctx);

    size_t sl;
    const char *stream = NexCacheModule_StringPtrLen(argv[1], &sl);
    char streambuf[256];
    if (sl == 0 || sl >= sizeof(streambuf)) return NexCacheModule_ReplyWithError(ctx, "ERR nome stream non valido");
    memcpy(streambuf, stream, sl);
    streambuf[sl] = '\0';

    size_t kl, vl;
    const char *key = NexCacheModule_StringPtrLen(argv[2], &kl);
    const char *val = NexCacheModule_StringPtrLen(argv[3], &vl);
    char keybuf[64], valbuf[64];
    if (kl >= sizeof(keybuf) || vl >= sizeof(valbuf))
        return NexCacheModule_ReplyWithError(ctx, "ERR key/value troppo lunghi");
    memcpy(keybuf, key, kl); keybuf[kl] = '\0';
    memcpy(valbuf, val, vl); valbuf[vl] = '\0';

    int rc = stream_bp_config(streambuf, keybuf, valbuf);
    if (rc != 0) return NexCacheModule_ReplyWithError(ctx, "ERR XBP.CONFIG fallito (chiave sconosciuta o stream non inizializzato)");
    return NexCacheModule_ReplyWithSimpleString(ctx, "OK");
}

int NexCacheModule_OnLoad(NexCacheModuleCtx *ctx, NexCacheModuleString **argv, int argc) {
    NEXCACHEMODULE_NOT_USED(argv);
    NEXCACHEMODULE_NOT_USED(argc);

    if (NexCacheModule_Init(ctx, "nexbp", 1, NEXCACHEMODULE_APIVER_1) == NEXCACHEMODULE_ERR) return NEXCACHEMODULE_ERR;

    if (NexCacheModule_CreateCommand(ctx, "xbp.init", XBPInit_NexCacheCommand, "write deny-oom", 0, 0, 0) ==
        NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "xbp.add", XBPAdd_NexCacheCommand, "write deny-oom", 0, 0, 0) ==
        NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "xbp.ack", XBPAck_NexCacheCommand, "write", 0, 0, 0) == NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "xbp.info", XBPInfo_NexCacheCommand, "readonly", 0, 0, 0) ==
        NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;
    if (NexCacheModule_CreateCommand(ctx, "xbp.config", XBPConfig_NexCacheCommand, "write", 0, 0, 0) ==
        NEXCACHEMODULE_ERR)
        return NEXCACHEMODULE_ERR;

    return NEXCACHEMODULE_OK;
}
