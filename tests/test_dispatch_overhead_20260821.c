/* NexCache — Costo reale del "risveglia un worker, aspetta il completamento"
 * ============================================================
 * Il prototipo test_shard_parallel_read_20260821.c ha misurato thread
 * lettori GIA' IN ESECUZIONE in un loop stretto -- zero costo di risveglio
 * per singola richiesta. Il vero motore, collegato al path client, dovrebbe
 * invece svegliare un worker per OGNI comando in arrivo e aspettarne il
 * completamento prima di rispondere al client -- un pattern sincrono di
 * "dispatch + wait" per ogni singola operazione.
 *
 * Questo e' esattamente il tipo di costo che ha gia' fatto PEGGIORARE le
 * prestazioni quando abbiamo provato --io-threads su questo fork (SET -P16:
 * 928k a io-threads=1, sceso a 328k a io-threads=8). Prima di modificare il
 * path di esecuzione comandi del server live, questo test isola e misura
 * SOLO quel costo di andata e ritorno, confrontato con l'esecuzione locale
 * diretta (nessun dispatch), per rispondere alla domanda: il risveglio di
 * un thread condvar-based e' abbastanza economico da giustificare il
 * parallelismo per operazioni piccole come una GET da 32 byte?
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Un "worker" permanente, sveglia-per-lavoro-esegui-notifica ────────── */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond_work;   /* segnalato dal thread principale: c'e' lavoro */
    pthread_cond_t cond_done;   /* segnalato dal worker: lavoro completato */
    int has_work;
    int done;
    int running;
    volatile long result;
    pthread_t thread;
} Worker;

static void *worker_main(void *arg) {
    Worker *w = (Worker *)arg;
    pthread_mutex_lock(&w->mutex);
    while (w->running) {
        while (!w->has_work && w->running) {
            pthread_cond_wait(&w->cond_work, &w->mutex);
        }
        if (!w->running) break;
        /* "Lavoro": simula una lookup nel kvstore -- costo trascurabile
         * rispetto al vero find, per isolare SOLO il costo del dispatch. */
        w->result = w->result + 1;
        w->has_work = 0;
        w->done = 1;
        pthread_cond_signal(&w->cond_done);
    }
    pthread_mutex_unlock(&w->mutex);
    return NULL;
}

static void worker_start(Worker *w) {
    pthread_mutex_init(&w->mutex, NULL);
    pthread_cond_init(&w->cond_work, NULL);
    pthread_cond_init(&w->cond_done, NULL);
    w->has_work = 0;
    w->done = 0;
    w->running = 1;
    w->result = 0;
    pthread_create(&w->thread, NULL, worker_main, w);
}

static void worker_stop(Worker *w) {
    pthread_mutex_lock(&w->mutex);
    w->running = 0;
    pthread_cond_signal(&w->cond_work);
    pthread_mutex_unlock(&w->mutex);
    pthread_join(w->thread, NULL);
}

/* Dispatch sincrono: sveglia il worker, aspetta che finisca. Questo e'
 * ESATTAMENTE il pattern che servirebbe nel path client reale: il thread
 * principale non puo' continuare a scrivere la risposta finche' il worker
 * non ha finito. */
static void dispatch_and_wait(Worker *w) {
    pthread_mutex_lock(&w->mutex);
    w->has_work = 1;
    w->done = 0;
    pthread_cond_signal(&w->cond_work);
    while (!w->done) {
        pthread_cond_wait(&w->cond_done, &w->mutex);
    }
    pthread_mutex_unlock(&w->mutex);
}

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

int main(int argc, char **argv) {
    int n_ops = (argc > 1) ? atoi(argv[1]) : 500000;

    /* ── Baseline: nessun dispatch, lavoro eseguito localmente ──────────── */
    volatile long local_result = 0;
    double t0 = now_us();
    for (int i = 0; i < n_ops; i++) local_result++;
    double t1 = now_us();
    double local_ops_per_sec = n_ops / ((t1 - t0) / 1e6);

    /* ── Dispatch sincrono verso 1 worker permanente ────────────────────── */
    Worker w;
    worker_start(&w);
    t0 = now_us();
    for (int i = 0; i < n_ops; i++) dispatch_and_wait(&w);
    t1 = now_us();
    double dispatch_ops_per_sec = n_ops / ((t1 - t0) / 1e6);
    double per_op_overhead_us = ((t1 - t0) / n_ops);
    worker_stop(&w);

    printf("Operazioni per round: %d\n\n", n_ops);
    printf("%-45s %-18s\n", "Scenario", "ops/sec");
    printf("--------------------------------------------------------------\n");
    printf("%-45s %-18.0f\n", "Esecuzione locale (nessun dispatch)", local_ops_per_sec);
    printf("%-45s %-18.0f\n", "Dispatch+wait verso 1 worker (condvar)", dispatch_ops_per_sec);
    printf("\nOverhead per singolo dispatch sincrono: %.3f microsecondi\n", per_op_overhead_us);
    printf("Rapporto dispatch/locale: %.4fx (piu' basso di 1.0 = il dispatch e' un costo netto)\n",
           dispatch_ops_per_sec / local_ops_per_sec);

    printf("\nPASS\n");
    return 0;
}
