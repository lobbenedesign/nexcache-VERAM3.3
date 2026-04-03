/* NexCache Multi-Thread Core Engine — MODULO 3
 * ============================================================
 * Questo è il modulo più differenziante rispetto a NexCache.
 *
 * NexCache: 1 thread principale processa TUTTI i comandi → bottleneck.
 * NexCache: N worker thread, ognuno gestisce una partizione dell'hash table.
 * Risultato: scaling lineare con il numero di core CPU.
 *
 * Schema:
 *   16384 slot (compatibili NexCache Cluster)
 *   = N worker × (16384/N) slot per worker
 *
 *   Worker 0 → slot 0..255
 *   Worker 1 → slot 256..511
 *   ...
 *
 *   Ogni worker ha la sua Arena → zero lock per allocazioni.
 *   La coda comandi è MPSC lock-free → zero lock per dispatch.
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#ifndef NEXCACHE_ENGINE_H
#define NEXCACHE_ENGINE_H

#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include "../memory/arena.h"
#include "../memory/tagged_ptr.h"
#include "../vera_lockfree.h"
#include "vll.h"

/* ── Costanti engine ────────────────────────────────────────── */
#define NEX_MAX_WORKERS 16
#define NEX_HASH_SLOTS 16384   /* Compatibile NexCache Cluster */
#define NEX_CMD_RING_SIZE 32768 /* Elementi nel ring buffer (potenza 2) */
#define NEX_CMD_RING_MASK (NEX_CMD_RING_SIZE - 1)
#define NEX_MAX_CMD_SIZE 1024  /* Dimensione massima un comando */
#define NEX_MAX_INLINE_ARGS 32 /* Max argomenti inline per comando */
#define NEX_LATENCY_BUCKETS 16 /* Bucket per istogramma latenze */

/* ── Tipi di comando ────────────────────────────────────────── */
typedef enum NexCmdType {
    /* Comandi base NexCache-compatibili */
    NEX_CMD_GET = 0,
    NEX_CMD_SET = 1,
    NEX_CMD_DEL = 2,
    NEX_CMD_MGET = 3,
    NEX_CMD_MSET = 4,
    NEX_CMD_INCR = 5,
    NEX_CMD_DECR = 6,
    NEX_CMD_EXPIRE = 7,
    NEX_CMD_TTL = 8,
    NEX_CMD_TYPE = 9,
    NEX_CMD_EXISTS = 10,
    /* Comandi NexCache-specifici */
    NEX_CMD_VADD = 100,  /* Vector ADD */
    NEX_CMD_VSIM = 101,  /* Vector SIMilarity search */
    NEX_CMD_SCADD = 102, /* Semantic Cache ADD */
    NEX_CMD_SCGET = 103, /* Semantic Cache GET */
    /* Controllo engine */
    NEX_CMD_SHUTDOWN = 999,
} NexCmdType;

/* ── Struttura di un comando ────────────────────────────────── */
typedef struct __attribute__((aligned(256))) NexCmd {
    NexCmdType type;
    uint64_t client_id;    /* ID del client che ha inviato il comando */
    uint64_t issued_at_us; /* Timestamp emissione (µs) */

    /* Argomenti inline per comandi semplici */
    int argc;
    const char *argv[NEX_MAX_INLINE_ARGS];
    size_t argl[NEX_MAX_INLINE_ARGS]; /* Lunghezze argomenti */

    /* Buffer per risposta */
    char *reply_buf;
    size_t reply_len;
    size_t reply_cap;

    /* Callback chiamata dal worker quando il comando è completato */
    void (*on_complete)(struct NexCmd *cmd, void *userdata);
    void *userdata;

    /* NEX-VERA: MPSC Node (Vyukov-GODMODE) */
    mpsc_node_t mpsc_node;
} NexCmd;

/* ── Istogramma latenze ─────────────────────────────────────── */
typedef struct LatencyHistogram {
    /* Bucket in µs: <1, 1-2, 2-4, 4-8, 8-16, 16-32, 32-64, 64-128,
       128-256, 256-512, 512-1024, 1ms-2ms, 2ms-4ms, 4ms-8ms, 8ms-16ms, >16ms */
    uint64_t buckets[NEX_LATENCY_BUCKETS];
    double p50_us;
    double p99_us;
    double p999_us;
    double max_us;
    uint64_t total_samples;
} LatencyHistogram;

/* ── Struttura Worker Thread ────────────────────────────────── */
typedef struct __attribute__((aligned(256))) NexWorker {
    int id;           /* ID worker (0..num_workers-1) */
    pthread_t thread; /* Thread POSIX handle */
    int slot_start;   /* Primo slot gestito */
    int slot_end;     /* Ultimo slot gestito (esclusivo) */

    /* Arena dedicata — zero lock, zero contesa */
    Arena *arena;

    /* NEX-VERA: MPSC Lock-free Queue (Phase 3)
     * Sostituisce il ring buffer con una coda di Vyukov scalabile per Rubin. */
    mpsc_queue_t cmd_queue;

    /* NEX-VERA: Scheduler Ring Buffer (Phase 4 - Work Stealing)
     * Campi necessari per core/scheduler.c */
    _Atomic uint64_t cmd_head;
    _Atomic uint64_t cmd_tail;
    NexCmd *cmd_ring[NEX_CMD_RING_SIZE];

    /* Hash table locale per i dati di questo worker
     * Accesso senza lock (un solo writer: questo worker) */
    void *local_dict; /* Puntatore alla dict locale */

    /* Statistiche per worker */
    _Atomic uint64_t cmds_processed;
    _Atomic uint64_t bytes_in;
    _Atomic uint64_t bytes_out;
    _Atomic uint64_t cache_hits;
    _Atomic uint64_t cache_misses;
    LatencyHistogram latency;

    /* Flag stato */
    volatile int running;
    int cpu_affinity; /* CPU core affinity (-1 = auto) */
} NexWorker;

/* ── Struttura Engine Principale ────────────────────────────── */
typedef struct NexEngine {
    NexWorker workers[NEX_MAX_WORKERS];
    int num_workers;      /* Worker attivi */
    volatile int running; /* Flag globale running */

    /* Arena globale per strutture condivise tra worker */
    Arena *global_arena;

    /* VLL Transaction Manager — Lock granulari deterministici */
    VLLManager *vll;

    /* Configurazione */
    int port;
    char bind_addr[64];
    size_t max_memory_mb;
    int tcp_backlog;

    /* Statistiche globali */
    _Atomic uint64_t total_connections;
    _Atomic uint64_t active_connections;
    _Atomic uint64_t total_commands;
    uint64_t started_at_us; /* Timestamp avvio */
} NexEngine;

/* ── API pubblica ───────────────────────────────────────────── */

/**
 * engine_create - Crea e inizializza l'engine.
 * @num_workers: Numero di worker thread (0 = auto-detect dai core CPU)
 * @port: Porta di ascolto (default 6379)
 * @bind_addr: Indirizzo bind (NULL = "127.0.0.1")
 *
 * Returns: puntatore all'engine, NULL su errore.
 */
NexEngine *engine_create(int num_workers, int port, const char *bind_addr);

/**
 * engine_start - Avvia tutti i worker thread e il networking.
 * Returns: 0 su successo, -1 su errore.
 */
int engine_start(NexEngine *engine);

/**
 * engine_stop - Ferma tutti i worker (graceful shutdown).
 */
void engine_stop(NexEngine *engine);

/**
 * engine_destroy - Libera tutte le risorse.
 */
void engine_destroy(NexEngine *engine);

/**
 * engine_dispatch_cmd - Invia un comando al worker corretto per la chiave.
 * Thread-safe (può essere chiamata da qualsiasi thread networking).
 *
 * @engine: Engine
 * @cmd:    Comando da dispatchare
 * @key:    Chiave su cui opera il comando
 * @keylen: Lunghezza chiave
 *
 * Returns: 0 su successo, -1 se la coda è piena (back-pressure).
 */
int engine_dispatch_cmd(NexEngine *engine, NexCmd *cmd, const char *key, size_t keylen);

/**
 * engine_worker_for_key - Determina quale worker gestisce una chiave.
 * Usa CRC16 compatibile con NexCache Cluster.
 */
int engine_worker_for_key(NexEngine *engine, const char *key, size_t keylen);

/**
 * engine_get_stats - Statistiche aggregate di tutti i worker.
 */
void engine_print_stats(NexEngine *engine);

/**
 * engine_auto_workers - Determina il numero ottimale di worker basato sui core.
 * Usa il 75% dei core disponibili (lascia spazio per I/O thread).
 */
int engine_auto_workers(void);

/* ── Engine globale ─────────────────────────────────────────── */
extern NexEngine *g_engine;

#endif /* NEXCACHE_ENGINE_H */
