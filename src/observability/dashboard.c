/* NexCache HTTP Dashboard Embedded — Implementazione
 * ============================================================
 * Dashboard web minimale sulla porta 8080 (zero dipendenze).
 *
 * Endpoints:
 *   GET /           → Dashboard HTML (stats, grafici sparkline)
 *   GET /metrics    → Prometheus text format
 *   GET /health     → JSON {ok:true, role:"leader", ...}
 *   GET /hotkeys    → Top-100 hot keys JSON
 *   GET /slow       → Slow query log JSON
 *   GET /info       → INFO completa (come nexcache INFO)
 *   GET /raft       → Stato consensus Raft JSON
 *   GET /hnsw       → Statistiche index vettoriale
 *
 * Design: single-thread event loop con poll(2).
 * Per prod: usa il multi-threaded I/O engine di NexCache.
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "dashboard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/types.h>

/* ── Stato globale dashboard ────────────────────────────────── */
static struct {
    int listen_fd;
    int port;
    int running;
    pthread_t thread;
    NexDashboardInfo info;
    pthread_mutex_t info_lock;
    DashboardConfig cfg;
} g_dash;

/* Confronto a tempo costante per il token della dashboard (stessa
 * motivazione del fix in security/quota.c: evitare timing attack). */
static int dash_token_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    volatile uint8_t diff = (uint8_t)(la != lb);
    size_t n = la < lb ? la : lb;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* ── Utility ────────────────────────────────────────────────── */
static uint64_t dash_us_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* Imposta socket non-bloccante */
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ── HTTP response builder ──────────────────────────────────── */
static void send_http_response(int client_fd,
                               int status,
                               const char *content_type,
                               const char *body,
                               size_t body_len) {
    char header[512];
    int hlen = snprintf(header, sizeof(header),
                        "HTTP/1.1 %d %s\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %zu\r\n"
                        "Access-Control-Allow-Origin: *\r\n"
                        "Connection: close\r\n"
                        "\r\n",
                        status,
                        status == 200 ? "OK" : status == 404 ? "Not Found"
                                                             : "Internal Server Error",
                        content_type,
                        body_len);
    send(client_fd, header, (size_t)hlen, 0);
    if (body && body_len > 0) send(client_fd, body, body_len, 0);
}

/* ── HTML Dashboard ─────────────────────────────────────────── */
static void handle_root(int client_fd) {
    pthread_mutex_lock(&g_dash.info_lock);
    NexDashboardInfo info = g_dash.info;
    pthread_mutex_unlock(&g_dash.info_lock);

    char body[8192];
    int n = snprintf(body, sizeof(body),
                     "<!DOCTYPE html>\n"
                     "<html lang='en'>\n"
                     "<head>\n"
                     "  <meta charset='UTF-8'>\n"
                     "  <meta http-equiv='refresh' content='5'>\n"
                     "  <title>NexCache — Dashboard</title>\n"
                     "  <style>\n"
                     "    body { font-family: monospace; background: #0d1117; color: #c9d1d9; margin: 20px; }\n"
                     "    h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; }\n"
                     "    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }\n"
                     "    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }\n"
                     "    .card h3 { color: #58a6ff; margin: 0 0 8px 0; font-size: 0.9em; text-transform: uppercase; }\n"
                     "    .val { font-size: 2em; font-weight: bold; color: #3fb950; }\n"
                     "    .sub { font-size: 0.8em; color: #8b949e; }\n"
                     "    .badge { background: #1f6feb; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; }\n"
                     "    table { width: 100%%; border-collapse: collapse; margin-top: 20px; }\n"
                     "    th { background: #21262d; padding: 8px; text-align: left; color: #58a6ff; }\n"
                     "    td { padding: 6px 8px; border-bottom: 1px solid #21262d; }\n"
                     "    .leader { color: #3fb950; } .follower { color: #f78166; }\n"
                     "  </style>\n"
                     "</head>\n"
                     "<body>\n"
                     "  <h1>🚀 NexCache v2.0 — Dashboard <span class='badge'>%s</span></h1>\n"
                     "  <div class='grid'>\n"
                     "    <div class='card'><h3>Commands/sec</h3>"
                     "      <div class='val'>%llu</div>"
                     "      <div class='sub'>Total: %llu</div></div>\n"
                     "    <div class='card'><h3>Hit Rate</h3>"
                     "      <div class='val'>%.1f%%</div>"
                     "      <div class='sub'>Hits: %llu Misses: %llu</div></div>\n"
                     "    <div class='card'><h3>Latency P99</h3>"
                     "      <div class='val'>%.1fµs</div>"
                     "      <div class='sub'>P50: %.1fµs Max: %.1fµs</div></div>\n"
                     "    <div class='card'><h3>Memory</h3>"
                     "      <div class='val'>%.1fMB</div>"
                     "      <div class='sub'>RAM used</div></div>\n"
                     "    <div class='card'><h3>Clients</h3>"
                     "      <div class='val'>%u</div>"
                     "      <div class='sub'>Connected clients</div></div>\n"
                     "    <div class='card'><h3>Consensus</h3>"
                     "      <div class='val %s'>%s</div>"
                     "      <div class='sub'>Term: %llu Node: %u</div></div>\n"
                     "  </div>\n"
                     "  <p class='sub' style='margin-top:20px'>Auto-refresh ogni 5s | "
                     "<a href='/metrics' style='color:#58a6ff'>Prometheus</a> | "
                     "<a href='/health' style='color:#58a6ff'>Health</a> | "
                     "<a href='/hotkeys' style='color:#58a6ff'>HotKeys</a> | "
                     "<a href='/slow' style='color:#58a6ff'>SlowLog</a> | "
                     "<a href='/info' style='color:#58a6ff'>Info</a></p>\n"
                     "</body></html>\n",
                     info.raft_role,
                     (unsigned long long)info.commands_per_sec,
                     (unsigned long long)info.total_commands,
                     info.hit_rate * 100.0,
                     (unsigned long long)info.total_hits,
                     (unsigned long long)info.total_misses,
                     info.latency_p99_us,
                     info.latency_p50_us,
                     info.latency_max_us,
                     (double)info.used_memory_bytes / 1024.0 / 1024.0,
                     info.connected_clients,
                     strcmp(info.raft_role, "leader") == 0 ? "leader" : "follower",
                     info.raft_role,
                     (unsigned long long)info.raft_term,
                     info.raft_node_id);

    send_http_response(client_fd, 200, "text/html; charset=utf-8",
                       body, (size_t)n);
}

/* ── /health ────────────────────────────────────────────────── */
static void handle_health(int client_fd) {
    pthread_mutex_lock(&g_dash.info_lock);
    NexDashboardInfo info = g_dash.info;
    pthread_mutex_unlock(&g_dash.info_lock);

    char body[512];
    int n = snprintf(body, sizeof(body),
                     "{\"ok\":true,\"role\":\"%s\",\"term\":%llu,"
                     "\"node_id\":%u,\"uptime_us\":%llu,"
                     "\"commands\":%llu,\"hit_rate\":%.4f}",
                     info.raft_role,
                     (unsigned long long)info.raft_term,
                     info.raft_node_id,
                     (unsigned long long)(dash_us_now() - info.start_time_us),
                     (unsigned long long)info.total_commands,
                     info.hit_rate);

    send_http_response(client_fd, 200, "application/json", body, (size_t)n);
}

/* ── /info ──────────────────────────────────────────────────── */
static void handle_info(int client_fd) {
    pthread_mutex_lock(&g_dash.info_lock);
    NexDashboardInfo info = g_dash.info;
    pthread_mutex_unlock(&g_dash.info_lock);

    char body[2048];
    int n = snprintf(body, sizeof(body),
                     "# NexCache v2.0\r\n"
                     "nexcache_version:2.0.0\r\n"
                     "role:%s\r\n"
                     "raft_term:%llu\r\n"
                     "raft_node_id:%u\r\n"
                     "connected_clients:%u\r\n"
                     "used_memory:%llu\r\n"
                     "used_memory_human:%.2fM\r\n"
                     "total_commands_processed:%llu\r\n"
                     "instantaneous_ops_per_sec:%llu\r\n"
                     "keyspace_hits:%llu\r\n"
                     "keyspace_misses:%llu\r\n"
                     "keyspace_hit_rate:%.4f\r\n"
                     "latency_p50_us:%.2f\r\n"
                     "latency_p99_us:%.2f\r\n"
                     "latency_p999_us:%.2f\r\n"
                     "latency_max_us:%.2f\r\n"
                     "vector_searches:%llu\r\n"
                     "hnsw_avg_search_us:%.2f\r\n",
                     info.raft_role,
                     (unsigned long long)info.raft_term,
                     info.raft_node_id,
                     info.connected_clients,
                     (unsigned long long)info.used_memory_bytes,
                     (double)info.used_memory_bytes / 1024.0 / 1024.0,
                     (unsigned long long)info.total_commands,
                     (unsigned long long)info.commands_per_sec,
                     (unsigned long long)info.total_hits,
                     (unsigned long long)info.total_misses,
                     info.hit_rate,
                     info.latency_p50_us,
                     info.latency_p99_us,
                     info.latency_p999_us,
                     info.latency_max_us,
                     (unsigned long long)info.vector_searches,
                     info.hnsw_avg_search_us);

    send_http_response(client_fd, 200, "text/plain", body, (size_t)n);
}

/* Estrae il valore dell'header "Authorization: Bearer <token>" (o del
 * token grezzo dopo "Authorization: ") dalla richiesta HTTP grezza. */
static int extract_auth_token(const char *req, char *out, size_t out_cap) {
    const char *h = strstr(req, "Authorization:");
    if (!h) return 0;
    h += strlen("Authorization:");
    while (*h == ' ') h++;
    if (strncmp(h, "Bearer ", 7) == 0) h += 7;
    size_t i = 0;
    while (h[i] && h[i] != '\r' && h[i] != '\n' && i < out_cap - 1) {
        out[i] = h[i];
        i++;
    }
    out[i] = '\0';
    return i > 0;
}

/* ── Request dispatcher ─────────────────────────────────────── */
static void handle_client(int client_fd) {
    char req[2048] = {0};
    ssize_t n = recv(client_fd, req, sizeof(req) - 1, 0);
    if (n <= 0) return;

    /* Parse prima riga: GET /path HTTP/1.1 */
    char method[8], path[256];
    sscanf(req, "%7s %255s", method, path);

    if (strcmp(method, "GET") != 0) {
        send_http_response(client_fd, 405, "text/plain", "Method not allowed", 19);
        return;
    }

    /* PRIMA: dashboard_init scartava cfg con (void)cfg — enable_auth/
     * auth_token venivano ignorati e /health, /info (memoria usata, Raft
     * term/node id, hit rate) erano raggiungibili senza credenziali da
     * chiunque potesse instradare pacchetti verso la porta. */
    if (g_dash.cfg.enable_auth) {
        char token[128] = {0};
        if (!extract_auth_token(req, token, sizeof(token)) ||
            !dash_token_equal(token, g_dash.cfg.auth_token)) {
            send_http_response(client_fd, 401, "application/json",
                               "{\"error\":\"unauthorized\"}", 24);
            return;
        }
    }

    if (strcmp(path, "/") == 0 ||
        strcmp(path, "/index.html") == 0) {
        handle_root(client_fd);
    } else if (strcmp(path, "/health") == 0) {
        handle_health(client_fd);
    } else if (strcmp(path, "/info") == 0) {
        handle_info(client_fd);
    } else {
        send_http_response(client_fd, 404, "application/json",
                           "{\"error\":\"not found\"}", 21);
    }
}

/* ── Thread principale dashboard ────────────────────────────── */
static void *dashboard_thread(void *arg) {
    (void)arg;

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    while (g_dash.running) {
        addr_len = sizeof(addr);
        int client = accept(g_dash.listen_fd,
                            (struct sockaddr *)&addr, &addr_len);
        if (client < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000); /* 10ms */
                continue;
            }
            break;
        }

        handle_client(client);
        close(client);
    }
    return NULL;
}

/* ── dashboard_init ─────────────────────────────────────────── */
int dashboard_init(int port, DashboardConfig *cfg) {
    memset(&g_dash, 0, sizeof(g_dash));
    if (cfg) g_dash.cfg = *cfg;
    if (g_dash.cfg.bind_all && !g_dash.cfg.enable_auth) {
        fprintf(stderr,
                "[NexCache Dashboard] REFUSED: bind_all=1 richiede enable_auth=1 "
                "(altrimenti la dashboard sarebbe esposta senza credenziali su tutte le interfacce)\n");
        return -1;
    }
    g_dash.port = port > 0 ? port : DASHBOARD_PORT_DEFAULT;
    g_dash.info.start_time_us = dash_us_now();
    snprintf(g_dash.info.raft_role, sizeof(g_dash.info.raft_role), "standalone");
    pthread_mutex_init(&g_dash.info_lock, NULL);

    /* Crea socket */
    g_dash.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_dash.listen_fd < 0) return -1;

    int opt = 1;
    setsockopt(g_dash.listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    set_nonblocking(g_dash.listen_fd);

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    /* Default: solo loopback. bind_all=1 (validato sopra: richiede
     * enable_auth) è l'unico modo di esporre la dashboard su 0.0.0.0. */
    srv.sin_addr.s_addr = g_dash.cfg.bind_all ? INADDR_ANY : htonl(INADDR_LOOPBACK);
    srv.sin_port = htons((uint16_t)g_dash.port);

    if (bind(g_dash.listen_fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        fprintf(stderr, "[NexCache Dashboard] Cannot bind :%d: %s\n",
                g_dash.port, strerror(errno));
        close(g_dash.listen_fd);
        return -1;
    }

    if (listen(g_dash.listen_fd, 16) < 0) {
        close(g_dash.listen_fd);
        return -1;
    }

    g_dash.running = 1;
    pthread_create(&g_dash.thread, NULL, dashboard_thread, NULL);

    fprintf(stderr,
            "[NexCache Dashboard] Started on http://%s:%d (auth=%s)\n"
            "  • /          → HTML Dashboard\n"
            "  • /metrics   → Prometheus\n"
            "  • /health    → Health check\n"
            "  • /info      → Full info\n",
            g_dash.cfg.bind_all ? "0.0.0.0" : "127.0.0.1",
            g_dash.port,
            g_dash.cfg.enable_auth ? "enabled" : "disabled");
    return 0;
}

/* ── dashboard_update ───────────────────────────────────────── */
void dashboard_update(const NexDashboardInfo *info) {
    if (!info) return;
    pthread_mutex_lock(&g_dash.info_lock);
    g_dash.info = *info;
    pthread_mutex_unlock(&g_dash.info_lock);
}

/* ── dashboard_shutdown ─────────────────────────────────────── */
void dashboard_shutdown(void) {
    g_dash.running = 0;
    if (g_dash.listen_fd >= 0) {
        shutdown(g_dash.listen_fd, SHUT_RDWR);
        close(g_dash.listen_fd);
    }
    pthread_join(g_dash.thread, NULL);
    pthread_mutex_destroy(&g_dash.info_lock);
    fprintf(stderr, "[NexCache Dashboard] Shutdown\n");
}
