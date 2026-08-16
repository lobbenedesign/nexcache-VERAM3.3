/* NexCache Work Stealing Scheduler — MODULO 3b (v2.0)
 * ============================================================
 * STATO ATTUALE: NON COLLEGATO al percorso di dispatch reale — nessuna
 * funzione di questo modulo (scheduler_create/try_steal/
 * update_utilization/print_stats) è chiamata da alcun punto del
 * codebase al di fuori di scheduler.c stesso (verificato con grep
 * globale). Inoltre opera su cmd_head/cmd_tail/cmd_ring (NexWorker in
 * engine.h), campi che engine.c inizializza ma non tocca mai altrove: il
 * dispatch reale (engine_dispatch_cmd/worker_thread_main) usa
 * esclusivamente la coda MPSC lock-free cmd_queue. Il risultato è che,
 * se mai qualcuno chiamasse scheduler_try_steal, il primo controllo di
 * profondità coda (`v_head <= v_tail + SCHED_STEAL_THRESHOLD`) sarebbe
 * sempre vero (0 <= 0 + soglia) e la funzione non ruberebbe mai nulla,
 * indipendentemente dallo squilibrio di carico reale sulla coda MPSC.
 * Le statistiche esposte (steals, rebalances, queue_depth) sarebbero
 * quindi sempre a zero — non fidarsi di questo modulo per bilanciamento
 * di carico reale finché non viene ricollegato. Ricollegarlo richiede o
 * (a) una vera coda work-stealing per worker (deque SPMC) al posto/in
 * aggiunta della MPSC, oppure (b) un adattamento dell'algoritmo per
 * operare direttamente sulla MPSC — nessuna delle due è stata tentata
 * qui: è un cambio di struttura dati sul percorso di dispatch caldo,
 * troppo rischioso da fare senza test di concorrenza dedicati (che oggi
 * non esistono per questo modulo).
 *
 * Bilancia automaticamente il carico tra i worker senza configurazione.
 *
 * Il problema:
 *   Con partizionamento statico degli slot (worker 0 → slot 0-255),
 *   un workload con hot key concentrate su pochi slot crea squilibrio:
 *   Worker 0: 90% CPU | Worker 1-7: 10% CPU
 *
 * La soluzione — Work Stealing:
 *   Worker idle → guarda le code dei worker più carichi →
 *   "ruba" comandi dalla coda del worker sovraccarico →
 *   li processa localmente con full coordination.
 *
 * Implementazione:
 *   Ogni worker ha una coda di lavoro locale (LIFO per cache locality).
 *   I worker idle eseguono scan periodici delle code altrui.
 *   Il furto avviene dalla TESTA della coda del worker sovraccarico
 *   (evita contesa con il worker che prende dalla CODA della propria).
 *
 * Basato su: Cilk work-stealing scheduler (MIT) + Go runtime scheduler
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#ifndef NEXCACHE_SCHEDULER_H
#define NEXCACHE_SCHEDULER_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include "../core/engine.h"

/* ── Costanti ───────────────────────────────────────────────── */
#define SCHED_STEAL_CHECK_US 100      /* Controlla furto ogni 100µs */
#define SCHED_STEAL_THRESHOLD 16      /* Ruba solo se queue depth > N */
#define SCHED_STEAL_BATCH_SIZE 4      /* Comandi da rubare per volta */
#define SCHED_IDLE_SLEEP_NS 1000      /* Sleep worker idle (1µs) */
#define SCHED_OVERLOAD_THRESHOLD 0.8f /* Worker "sovraccarico" a 80% queue */

/* ── Stato scheduler di un worker ──────────────────────────── */
typedef struct WorkerSchedState {
    _Atomic uint64_t queue_depth;     /* Profondità corrente della coda */
    _Atomic uint64_t steal_attempts;  /* Tentativi di furto effettuati */
    _Atomic uint64_t steal_successes; /* Furti riusciti (da altri worker) */
    _Atomic uint64_t stolen_from_me;  /* Comandi rubati da questa coda */
    _Atomic int is_idle;              /* 1 = worker in attesa di lavoro */
    double utilization;               /* % CPU usata (0.0-1.0) */
    uint64_t last_steal_us;           /* Ultimo furto effettuato */
} WorkerSchedState;

/* ── Scheduler globale ──────────────────────────────────────── */
typedef struct NexScheduler {
    NexEngine *engine;                        /* Engine parent */
    WorkerSchedState states[NEX_MAX_WORKERS]; /* Stato per worker */
    int enabled;                              /* 1 = work stealing attivo */

    /* Statistiche globali */
    _Atomic uint64_t total_steals;
    _Atomic uint64_t total_steal_fails;
    uint64_t rebalances;
    double avg_load_balance; /* 0=perfetto, 1=totalmente sbilanciato */
} NexScheduler;

/* ── API pubblica ───────────────────────────────────────────── */

/**
 * scheduler_create - Crea lo scheduler e lo aggancia all'engine.
 * @engine: Engine NexCache inizializzato
 * Returns: scheduler allocato, NULL su errore.
 */
NexScheduler *scheduler_create(NexEngine *engine);

/**
 * scheduler_enable - Abilita o disabilita il work stealing.
 * Può essere cambiato a runtime senza restart.
 */
void scheduler_enable(NexScheduler *sched, int enable);

/**
 * scheduler_try_steal - Tenta un furto da worker sovraccarichi.
 * Chiamato automaticamente dai worker quando la loro coda è vuota.
 *
 * @sched:      Scheduler
 * @my_worker:  ID del worker che vuole rubare
 * Returns: numero di comandi rubati (0 se nessuno disponibile).
 */
int scheduler_try_steal(NexScheduler *sched, int my_worker);

/**
 * scheduler_update_utilization - Aggiorna la misurazione di utilizzo.
 * Chiamato periodicamente dal worker per auto-riportare il suo carico.
 */
void scheduler_update_utilization(NexScheduler *sched,
                                  int worker_id,
                                  double util);

/**
 * scheduler_print_stats - Stampa lo stato del bilanciamento.
 */
void scheduler_print_stats(NexScheduler *sched);

/**
 * scheduler_destroy - Libera le risorse.
 */
void scheduler_destroy(NexScheduler *sched);

/* ── Algoritmo di selezione vittima ─────────────────────────── */
/*
 * Strategia di selezione del worker da cui rubare:
 *
 * 1. RANDOM con bias verso i più carichi:
 *    - Sceglie casualmente tra i worker con queue_depth > THRESHOLD
 *    - Riduce la contesa rispetto al "ruba sempre dal più carico"
 *
 * 2. LOCAL-VICTIM-FIRST:
 *    - Prima prova i worker "vicini" in NUMA topology
 *    - Riduce latenza di accesso alla memoria condivisa
 *
 * 3. POWER-OF-TWO-CHOICES:
 *    - Campiona 2 worker casuali, ruba dal più carico dei due
 *    - O(log log N) bilanciamento con contesa minima
 */

#endif /* NEXCACHE_SCHEDULER_H */
