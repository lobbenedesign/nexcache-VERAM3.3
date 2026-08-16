/* NexCache Protocol Auto-Fallback — Network Module (v5.0)
 * ============================================================
 * Rileva il supporto HW e applica un declassamento silente
 * alle connessioni qualora RDMA/DPDK non siano disponibili o
 * se un client standard attacca la porta TCP normale.
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "fallback_net.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_BACKENDS 3

/* Esterni (Stub per la dimostrazione architetturale o implementazioni reali) */
/* extern const NetBackend DpdkBackend;
 * extern const NetBackend IoUringBackend;
 * extern const NetBackend EpollBackend;
 *
 * Assumiamo siano definite in net_backend.h e compilate in dpdk_net.c etc.
 * Al fine del file, ricreiamo mock esterni se mancano per ora.
 */

/* Mock-ups se non sono presenti nel linker.
 * PRIMA: questo stub si chiamava "DpdkBackend" (minuscolo dopo la D),
 * mentre net_backend.h dichiara "extern const NetBackend DPDKBackend" e
 * dpdk_net.c definisce il simbolo forte "DPDKBackend" — nomi diversi,
 * quindi il linker non risolveva mai lo stub debole verso l'implementazione
 * reale: fb_init chiamava sempre e solo questo mock (init=NULL), mai
 * DPDKBackend da dpdk_net.c. Oggi è innocuo perché dpdk_init() ritorna
 * comunque sempre -1, ma il giorno in cui quel backend verrà implementato
 * davvero smetterà di essere agganciato, silenziosamente. */
const NetBackend __attribute__((weak)) DPDKBackend = {"dpdk", NULL, NULL, NULL, NULL, NULL};
const NetBackend __attribute__((weak)) IoUringBackend = {"io_uring", NULL, NULL, NULL, NULL, NULL};
const NetBackend __attribute__((weak)) EpollBackend = {"epoll", NULL, NULL, NULL, NULL, NULL};

static const NetBackend *active_backend = NULL;
static NetStats combined_stats = {0, 0, 0, 0, 0};

/* ── Fallback Logic Inizializzazione ───────────────────────────── */

static int fb_init(const char *interface, int num_queues) {
    const NetBackend *candidates[] = {
        &DPDKBackend,
        &IoUringBackend,
        &EpollBackend};

    printf("[Net] Auto-Fallback init avviato sull'interfaccia: %s\n", interface ? interface : "default");

    /* Tenta il binding hardware-accelerated o kernel-bypass in ordine decrescente di efficienza */
    for (int i = 0; i < MAX_BACKENDS; i++) {
        const NetBackend *b = candidates[i];
        if (b && b->init) {
            printf("[Net] Tentativo di inizializzazione backend: %s... ", b->name);
            if (b->init(interface, num_queues) == 0) {
                active_backend = b;
                printf("SUCCESSO (%s abilitato).\n", b->name);
                return 0;
            } else {
                printf("FALLITO. Declassamento (Fallback)...\n");
            }
        }
    }

    /* PRIMA: si dichiarava sempre successo assegnando EpollBackend come
     * "fallback sicuro" — ma EpollBackend non ha (qui) una vera
     * implementazione epoll dietro (init/recv/send sono NULL: nessun file
     * in questo modulo fornisce il simbolo forte). fb_recv/fb_send
     * ritornavano quindi silenziosamente 0 pacchetti per sempre, mentre
     * il chiamante credeva che l'inizializzazione fosse riuscita — questo
     * modulo di networking astratto (DPDK/io_uring/epoll pluggable) non è
     * oggi collegato al path client reale del server (quello usa
     * ae_epoll.c, il event loop Redis vanilla), ma se mai qualcuno lo
     * aggancia deve ricevere un errore onesto, non un falso OK.
     * ORA: si fallisce esplicitamente se nessun backend con una vera
     * implementazione ha inizializzato con successo. */
    fprintf(stderr,
            "[Net] Nessun backend di rete funzionante (DPDK/io_uring/epoll "
            "sono tutti stub non implementati in questo modulo) — init fallita.\n");
    active_backend = NULL;
    return -1;
}

/* ── Forward delle Operazioni ───────────────────────────────── */

static int fb_recv(struct NetPacket **pkts, int max_pkts) {
    if (active_backend && active_backend->recv) {
        return active_backend->recv(pkts, max_pkts);
    }
    return 0;
}

static int fb_send(struct NetPacket **pkts, int n_pkts) {
    if (active_backend && active_backend->send) {
        return active_backend->send(pkts, n_pkts);
    }
    return 0;
}

static void fb_free_pkt(struct NetPacket *pkt) {
    if (active_backend && active_backend->free_pkt) {
        active_backend->free_pkt(pkt);
    } else {
        /* Fallback deallocation standard se c'è payload */
        if (pkt && pkt->data) free(pkt->data);
        if (pkt) free(pkt);
    }
}

static void fb_stats(struct NetStats *out) {
    if (!out) return;
    if (active_backend && active_backend->stats) {
        active_backend->stats(out);
    } else {
        *out = combined_stats;
    }
}

/* ── Esposizione pubblica del Modulo AutoFallback ───────────── */

const NetBackend AutoFallbackBackend = {
    "auto_fallback",
    fb_init,
    fb_recv,
    fb_send,
    fb_free_pkt,
    fb_stats};
