/* NexCache Reactive Streams con Backpressure — MODULO 9 (v2.0)
 * ============================================================
 * NexCache Streams è potente ma NON gestisce la velocità del consumer.
 *
 * Il problema:
 *   Producer → 1M msg/sec
 *   Consumer → 100K msg/sec
 *   NexCache: riempie buffer → OOM → crash o eviction massiva
 *
 * La soluzione NexCache:
 *   Backpressure bidirezionale — il producer è rallentato
 *   automaticamente quando il consumer non riesce a stare al passo.
 *   Il consumer invia "credit" al producer: "ho processato N, mandane altri N".
 *
 * Ispirato a: Reactive Streams Specification (reactive-streams.org)
 * e: Akka Streams, Project Reactor, RxJava backpressure model
 *
 * Nuovi comandi NexCache:
 *   XADD_BP  <stream> <max_pending> <field> <value> [...]
 *   XREAD_BP <stream> <consumer_group> <count>
 *   XACK_BP  <stream> <consumer_group> <id...>
 *   XCONFIG  <stream> SET backpressure-strategy <BLOCK|DROP|SAMPLE>
 *   XCONFIG  <stream> SET max-pending <N>
 *   XBPINFO  <stream>
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#ifndef NEXCACHE_REACTIVE_H
#define NEXCACHE_REACTIVE_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

/* ── Strategie di backpressure ──────────────────────────────── */
typedef enum BackpressureStrategy {
    /* Blocca il producer fino a che c'è spazio disponibile.
     * Più sicuro, garantisce zero perdita messaggi.
     * Il producer riceve un errore LIMIT_REACHED o attende. */
    BP_STRATEGY_BLOCK = 0,

    /* Droppa i nuovi messaggi quando il buffer è pieno.
     * Utile per dati real-time dove la freschezza > completezza
     * (es. telemetria, metriche, log di debugging). */
    BP_STRATEGY_DROP = 1,

    /* Campiona: accetta solo ogni N-esimo messaggio quando sovraccarico.
     * Mantiene la forma statistica del flusso pur riducendo il volume. */
    BP_STRATEGY_SAMPLE = 2,

    /* Oldest-first eviction: rimuove i messaggi più vecchi
     * per fare spazio ai nuovi. Utile per stream di eventi recenti. */
    BP_STRATEGY_EVICT_OLD = 3,
} BackpressureStrategy;

/* ── Credit-based flow control ──────────────────────────────── */
/*
 * Schema credit-based (come TCP window, ma per messaggi):
 *
 *  Producer                    Buffer              Consumer
 *     │                          │                    │
 *     │─── XADD_BP (10 msg) ────▶│                    │
 *     │                          │─── XREAD_BP ──────▶│
 *     │                          │                    │ processa 5
 *     │◀── CREDIT +5 ────────────│◀── XACK_BP(5) ─────│
 *     │─── XADD_BP (5 msg) ─────▶│                    │
 *
 * Il producer non può inviare più di max_pending messaggi non confermati.
 * Quando il consumer conferma (ACK), il credito viene restituito.
 */

/* ── Struttura stato backpressure per stream ─────────────────── */
typedef struct StreamBackpressure {
    char name[256];                /* Nome dello stream */
    BackpressureStrategy strategy; /* Strategia backpressure */
    uint64_t max_pending;          /* Max messaggi non confermati */
    uint64_t current_pending;      /* Messaggi attualmente pending */
    uint64_t credit_total;         /* Credito totale disponibile */

    /* Statistiche */
    uint64_t msgs_produced;
    uint64_t msgs_consumed;
    uint64_t msgs_dropped;            /* Drop per BP_STRATEGY_DROP */
    uint64_t msgs_sampled;            /* Campionati per BP_STRATEGY_SAMPLE */
    uint64_t producer_blocks;         /* Volte che il producer è stato bloccato */
    uint64_t producer_block_us_total; /* Tempo totale di blocco del producer */
    double avg_producer_block_us;     /* Latenza media del blocco */
    double consumer_utilization;      /* % tempo consumer occupato */
    double producer_utilization;      /* % tempo producer occupato */
    double backpressure_ratio;        /* pending/max_pending */

    /* Sampling rate (per BP_STRATEGY_SAMPLE) */
    uint32_t sample_rate;    /* Accetta 1 ogni N messaggi */
    uint64_t sample_counter; /* Contatore per sampling */

    pthread_mutex_t lock;
} StreamBackpressure;

/* ── Consumer Group con backpressure ──────────────────────────  */
typedef struct BPConsumerGroup {
    char name[128];           /* Nome del consumer group */
    char stream_name[256];    /* Stream associato */
    uint64_t delivered_id;    /* Ultimo ID entrato */
    uint64_t ack_id;          /* Ultimo ID confermato */
    uint64_t pending_count;   /* Messaggi in pending */
    uint64_t credit_received; /* Credit ricevuto dai consumer */
    int members;              /* Numero di consumer attivi */
} BPConsumerGroup;

/* ── API pubblica ───────────────────────────────────────────── */

/**
 * stream_bp_init - Configura backpressure su uno stream.
 * @stream_name: Nome dello stream NexCache esistente
 * @strategy:    Strategia backpressure
 * @max_pending: Numero massimo messaggi non confermati
 *
 * Returns: 0 su successo, -1 su errore.
 */
int stream_bp_init(const char *stream_name,
                   BackpressureStrategy strategy,
                   uint64_t max_pending);

/**
 * stream_bp_add - XADD con backpressure (produce un messaggio).
 * Blocca, droppa o campiona in base alla strategia configurata.
 *
 * @stream_name: Stream target
 * @fields:      Array coppie field/value
 * @nfields:     Numero di coppie
 * @timeout_ms:  Timeout per BP_STRATEGY_BLOCK (0 = non blocca)
 * @out_id:      Output: ID del messaggio aggiunto
 *
 * Returns: 0 = aggiunto, 1 = droppato, 2 = campionato, -1 = errore.
 */
int stream_bp_add(const char *stream_name,
                  const char **fields,
                  int nfields,
                  uint32_t timeout_ms,
                  char *out_id,
                  size_t out_id_cap);

/**
 * stream_bp_read - Contabilità di credito per una XREAD con backpressure.
 *
 * IMPORTANTE (limite architetturale, non un bug isolato): questo modulo
 * NON possiede i dati dei messaggi — tiene solo un contatore di
 * "pending" per stream. @out_msgs NON viene mai popolato (era così anche
 * prima: il parametro era scartato con `(void)out_msgs`). Il vero
 * recupero dei messaggi deve avvenire chiamando XREADGROUP dello stream
 * engine reale (t_stream.c) SEPARATAMENTE; questa funzione va usata solo
 * per calcolare quanti messaggi il credito corrente permette di
 * consegnare e per aggiornare le statistiche — non come sostituto della
 * lettura vera. Integrarla operativamente con XREADGROUP è un lavoro di
 * wiring separato, non ancora fatto (nessun comando XREAD_BP esiste nel
 * command table).
 *
 * @stream_name:    Stream sorgente
 * @consumer_group: Consumer group
 * @consumer_name:  Nome del consumer specifico
 * @count:          Messaggi richiesti
 * @out_msgs:       Non popolato (vedi sopra) — riservato per una futura integrazione con t_stream.c
 * @out_count:      Numero di messaggi che il credito disponibile permette di consegnare
 *
 * Returns: 0 su successo, -1 su errore.
 */
int stream_bp_read(const char *stream_name,
                   const char *consumer_group,
                   const char *consumer_name,
                   uint32_t count,
                   void **out_msgs,
                   uint32_t *out_count);

/**
 * stream_bp_ack - Rilascia credit per @nids messaggi.
 *
 * IMPORTANTE: @ids non viene validato contro messaggi realmente pending
 * (questo modulo non tiene traccia degli ID, solo di un contatore
 * aggregato — vedi nota su stream_bp_read). Il rilascio di credito è
 * basato solo su @nids: un chiamante che passa un nids non corrispondente
 * ai messaggi davvero confermati dal consumer desincronizza il conteggio
 * di credito dal reale stato del consumer group. La validazione per-ID
 * richiederebbe integrare questo modulo con lo stream engine reale
 * (t_stream.c), non ancora fatto.
 *
 * @stream_name:    Stream
 * @consumer_group: Consumer group
 * @ids:            Non validato — vedi sopra
 * @nids:           Numero di messaggi per cui rilasciare credito (deve essere >= 0)
 *
 * Returns: numero di messaggi confermati (credito rilasciato), -1 su errore.
 */
int stream_bp_ack(const char *stream_name,
                  const char *consumer_group,
                  const char **ids,
                  int nids);

/**
 * stream_bp_info - Stats correnti del backpressure su uno stream.
 */
StreamBackpressure *stream_bp_get_info(const char *stream_name);

/**
 * stream_bp_print_stats - Stampa stats human-readable.
 */
void stream_bp_print_stats(const char *stream_name);

/**
 * stream_bp_config - Modifica configurazione runtime.
 */
int stream_bp_config(const char *stream_name,
                     const char *key,
                     const char *value);

#endif /* NEXCACHE_REACTIVE_H */
