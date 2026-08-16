/* NexCache Quota & Multi-Tenancy — Implementazione
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "quota.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* ── Stato globale ──────────────────────────────────────────── */
static Namespace g_namespaces[QUOTA_MAX_NAMESPACES];
static int g_ns_count = 0;
static int g_initialized = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Utility ────────────────────────────────────────────────── */
static uint64_t quota_us_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* ── quota_init ─────────────────────────────────────────────── */
int quota_init(void) {
    pthread_mutex_lock(&g_lock);
    memset(g_namespaces, 0, sizeof(g_namespaces));
    for (int i = 0; i < QUOTA_MAX_NAMESPACES; i++) {
        pthread_mutex_init(&g_namespaces[i].lock, NULL);
    }
    g_ns_count = 0;
    g_initialized = 1;
    pthread_mutex_unlock(&g_lock);
    fprintf(stderr, "[NexCache Quota] Multi-tenancy subsystem initialized\n");
    return 0;
}

/* ── quota_shutdown ─────────────────────────────────────────── */
void quota_shutdown(void) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_ns_count; i++) {
        Namespace *ns = &g_namespaces[i];
        for (int j = 0; j < ns->token_count; j++)
            free(ns->tokens[j]);
        free(ns->tokens);
        ns->tokens = NULL;
        ns->token_count = 0;
        ns->active = 0;
    }
    g_ns_count = 0;
    g_initialized = 0;
    pthread_mutex_unlock(&g_lock);
}

/* Confronto token a tempo costante: strcmp() esce al primo byte diverso,
 * lasciando che un attaccante di rete recuperi un token valido byte per
 * byte misurando i tempi di risposta di AUTH. pqcrypto.c usa già un
 * confronto costante per i propri token — qui non era stato applicato
 * nonostante sia esattamente lo stesso path (autenticazione client). */
static int ct_str_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    volatile uint8_t diff = (uint8_t)(la != lb);
    size_t n = la < lb ? la : lb;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    /* Se le lunghezze differiscono continuiamo comunque a leggere fino a
     * n byte da entrambe le stringhe (già fatto sopra): non ritorniamo
     * anticipatamente sulla mismatch di lunghezza per non reintrodurre
     * un side-channel sulla lunghezza del token memorizzato. */
    return diff == 0;
}

/* ── Trova namespace per nome ───────────────────────────────── */
static Namespace *ns_find_nolock(const char *name) {
    for (int i = 0; i < g_ns_count; i++) {
        if (g_namespaces[i].active &&
            strcmp(g_namespaces[i].config.name, name) == 0)
            return &g_namespaces[i];
    }
    return NULL;
}

/* ── quota_namespace_create ─────────────────────────────────── */
int quota_namespace_create(const NamespaceConfig *config) {
    if (!config || config->name[0] == '\0') return -1;

    pthread_mutex_lock(&g_lock);

    if (ns_find_nolock(config->name)) {
        pthread_mutex_unlock(&g_lock);
        return -1; /* Già esiste */
    }
    if (g_ns_count >= QUOTA_MAX_NAMESPACES) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }

    Namespace *ns = &g_namespaces[g_ns_count++];
    memcpy(&ns->config, config, sizeof(NamespaceConfig));

    memset(&ns->stats, 0, sizeof(NamespaceStats));
    strncpy(ns->stats.name, config->name, sizeof(ns->stats.name) - 1);

    ns->stats.created_at_us = quota_us_now();
    ns->ops_this_window = 0;
    ns->window_start_us = quota_us_now();
    ns->active = 1;
    ns->tokens = NULL;
    ns->token_count = 0;
    ns->token_cap = 0;

    pthread_mutex_unlock(&g_lock);

    fprintf(stderr,
            "[NexCache Quota] Namespace '%s' created: "
            "mem=%lluMB ops/s=%llu conns=%u\n",
            config->name,
            (unsigned long long)(config->max_memory_bytes / 1024 / 1024),
            (unsigned long long)config->max_ops_per_sec,
            config->max_connections);
    return 0;
}

/* ── quota_namespace_update ─────────────────────────────────── */
int quota_namespace_update(const char *name, const char *key, const char *value) {
    pthread_mutex_lock(&g_lock);
    Namespace *ns = ns_find_nolock(name);
    pthread_mutex_unlock(&g_lock);
    if (!ns) return -1;

    pthread_mutex_lock(&ns->lock);

    if (strcmp(key, "memory-limit") == 0) {
        uint64_t mb = (uint64_t)atoll(value);
        ns->config.max_memory_bytes = mb * 1024 * 1024;
    } else if (strcmp(key, "cpu-budget") == 0) {
        ns->config.cpu_budget_pct = atof(value);
    } else if (strcmp(key, "max-keys") == 0) {
        ns->config.max_keys = (uint64_t)atoll(value);
    } else if (strcmp(key, "max-connections") == 0) {
        ns->config.max_connections = (uint32_t)atoi(value);
    } else if (strcmp(key, "max-ops-per-sec") == 0) {
        ns->config.max_ops_per_sec = (uint64_t)atoll(value);
    } else if (strcmp(key, "default-ttl") == 0) {
        ns->config.default_ttl_secs = atoi(value);
    }

    pthread_mutex_unlock(&ns->lock);
    return 0;
}

/* ── quota_namespace_drop ───────────────────────────────────── */
/* PRIMA: mutava ns->tokens/token_count/token_cap tenendo solo g_lock,
 * mentre ogni altra funzione su questi campi (quota_auth_token_add,
 * quota_resolve_namespace, ...) usa ns->lock. quota_auth_token_add fa
 * lookup sotto g_lock, rilascia g_lock, POI acquisisce ns->lock — nella
 * finestra tra le due, un quota_namespace_drop concorrente su questa
 * stessa ns può liberare ns->tokens, impostarlo a NULL, e (bug aggiuntivo)
 * NON resettava token_cap: quota_auth_token_add allora vede
 * token_count(0) >= token_cap(stale, es. 8) falso, salta la realloc ed
 * esegue ns->tokens[0] = ... su un puntatore NULL → crash.
 * ORA: la mutazione dei token avviene sotto ns->lock come ovunque altrove,
 * e token_cap viene azzerato insieme a tokens. */
int quota_namespace_drop(const char *name) {
    pthread_mutex_lock(&g_lock);
    Namespace *ns = ns_find_nolock(name);
    if (!ns) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    ns->active = 0; /* sotto g_lock: impedisce nuovi lookup da ns_find_nolock */
    pthread_mutex_unlock(&g_lock);

    pthread_mutex_lock(&ns->lock);
    for (int i = 0; i < ns->token_count; i++) free(ns->tokens[i]);
    free(ns->tokens);
    ns->tokens = NULL;
    ns->token_count = 0;
    ns->token_cap = 0;
    memset(&ns->config, 0, sizeof(NamespaceConfig));
    pthread_mutex_unlock(&ns->lock);

    fprintf(stderr, "[NexCache Quota] Namespace '%s' dropped\n", name);
    return 0;
}

/* ── quota_namespace_evict ──────────────────────────────────── */
size_t quota_namespace_evict(const char *name, size_t target_mb) {
    pthread_mutex_lock(&g_lock);
    Namespace *ns = ns_find_nolock(name);
    pthread_mutex_unlock(&g_lock);
    if (!ns) return 0;

    /* TODO: integra con il memory manager per eviction effettiva */
    size_t freed_mb = target_mb; /* Stub: assume eviction riuscita */
    pthread_mutex_lock(&ns->lock);
    ns->stats.evictions_forced += freed_mb;
    if (ns->stats.used_memory_bytes > freed_mb * 1024 * 1024) {
        ns->stats.used_memory_bytes -= freed_mb * 1024 * 1024;
    }
    pthread_mutex_unlock(&ns->lock);
    return freed_mb;
}

/* ── quota_auth_token_add ───────────────────────────────────── */
int quota_auth_token_add(const char *ns_name, const char *token) {
    pthread_mutex_lock(&g_lock);
    Namespace *ns = ns_find_nolock(ns_name);
    pthread_mutex_unlock(&g_lock);
    if (!ns || !token) return -1;

    pthread_mutex_lock(&ns->lock);

    if (ns->token_count >= ns->token_cap) {
        int new_cap = ns->token_cap == 0 ? 8 : ns->token_cap * 2;
        char **newtok = (char **)realloc(ns->tokens, (size_t)new_cap * sizeof(char *));
        if (!newtok) {
            pthread_mutex_unlock(&ns->lock);
            return -1;
        }
        ns->tokens = newtok;
        ns->token_cap = new_cap;
    }
    ns->tokens[ns->token_count++] = strdup(token);
    pthread_mutex_unlock(&ns->lock);
    return 0;
}

/* ── quota_resolve_namespace ────────────────────────────────── */
int quota_resolve_namespace(const char *token, char *out_name, size_t out_cap) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_ns_count; i++) {
        Namespace *ns = &g_namespaces[i];
        if (!ns->active) continue;
        for (int j = 0; j < ns->token_count; j++) {
            if (ct_str_equal(ns->tokens[j], token)) {
                strncpy(out_name, ns->config.name, out_cap - 1);
                out_name[out_cap - 1] = '\0';
                pthread_mutex_unlock(&g_lock);
                return 0;
            }
        }
    }
    pthread_mutex_unlock(&g_lock);
    return -1;
}

/* ── quota_check ────────────────────────────────────────────── */
int quota_check(const char *ns_name, size_t bytes_in) {
    (void)bytes_in;
    if (!ns_name) return 0; /* Nessun namespace = nessun limite */

    pthread_mutex_lock(&g_lock);
    Namespace *ns = ns_find_nolock(ns_name);
    pthread_mutex_unlock(&g_lock);
    if (!ns) return 0;

    pthread_mutex_lock(&ns->lock);

    int result = 0; /* 0 = OK */

    /* Controlla memoria */
    if (ns->config.max_memory_bytes > 0 &&
        ns->stats.used_memory_bytes >= ns->config.max_memory_bytes) {
        ns->stats.quota_violations_memory++;
        if (ns->config.memory_action == QUOTA_ACTION_REJECT) {
            ns->stats.requests_rejected++;
            result = -1;
        } else if (ns->config.memory_action == QUOTA_ACTION_THROTTLE) {
            ns->stats.requests_throttled++;
            result = 1;
        }
    }

    /* Controlla ops/sec con sliding window */
    if (result == 0 && ns->config.max_ops_per_sec > 0) {
        uint64_t now = quota_us_now();
        uint64_t window_us = (uint64_t)QUOTA_WINDOW_SECS * 1000000ULL;

        if (now - ns->window_start_us >= window_us) {
            ns->ops_this_window = 0;
            ns->window_start_us = now;
        }
        ns->ops_this_window++;

        if (ns->ops_this_window > ns->config.max_ops_per_sec) {
            ns->stats.quota_violations_cpu++;
            if (ns->config.cpu_action == QUOTA_ACTION_REJECT) {
                ns->stats.requests_rejected++;
                result = -1;
            } else {
                ns->stats.requests_throttled++;
                result = 1;
            }
        }
    }

    /* Controlla max keys */
    if (result == 0 && ns->config.max_keys > 0 &&
        ns->stats.key_count >= ns->config.max_keys) {
        ns->stats.requests_rejected++;
        result = -1;
    }

    pthread_mutex_unlock(&ns->lock);
    return result;
}

/* ── quota_record ───────────────────────────────────────────── */
void quota_record(const char *ns_name, size_t bytes_in, size_t bytes_out, double latency_us, int is_hit) {
    if (!ns_name) return;

    pthread_mutex_lock(&g_lock);
    Namespace *ns = ns_find_nolock(ns_name);
    pthread_mutex_unlock(&g_lock);
    if (!ns) return;

    pthread_mutex_lock(&ns->lock);

    ns->stats.ops_total++;
    ns->stats.bytes_read += bytes_in;
    ns->stats.bytes_written += bytes_out;
    ns->stats.last_access_us = quota_us_now();

    if (is_hit)
        ns->stats.hits++;
    else
        ns->stats.misses++;

    /* Latenza rolling average */
    ns->stats.latency_p50_us = ns->stats.latency_p50_us * 0.99 +
                               latency_us * 0.01;
    ns->stats.latency_p99_us = ns->stats.latency_p99_us * 0.999 +
                               latency_us * 0.001;
    if (latency_us > ns->stats.latency_max_us)
        ns->stats.latency_max_us = latency_us;

    uint64_t total = ns->stats.hits + ns->stats.misses;
    ns->stats.hit_rate = total > 0 ? (double)ns->stats.hits / (double)total : 0.0;

    pthread_mutex_unlock(&ns->lock);
}

/* ── quota_namespace_stats ──────────────────────────────────── */
NamespaceStats quota_namespace_stats(const char *name) {
    NamespaceStats empty = {0};
    pthread_mutex_lock(&g_lock);
    Namespace *ns = ns_find_nolock(name);
    if (!ns) {
        pthread_mutex_unlock(&g_lock);
        return empty;
    }
    pthread_mutex_lock(&ns->lock);
    NamespaceStats s = ns->stats;
    pthread_mutex_unlock(&ns->lock);
    pthread_mutex_unlock(&g_lock);
    return s;
}

/* ── quota_list_namespaces ──────────────────────────────────── */
int quota_list_namespaces(char **out, int max) {
    pthread_mutex_lock(&g_lock);
    int count = 0;
    for (int i = 0; i < g_ns_count && count < max; i++) {
        if (g_namespaces[i].active) {
            out[count++] = g_namespaces[i].config.name;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return count;
}

/* ── quota_print_all_stats ──────────────────────────────────── */
void quota_print_all_stats(void) {
    pthread_mutex_lock(&g_lock);
    fprintf(stderr, "[NexCache Quota] Active namespaces: %d\n", g_ns_count);
    for (int i = 0; i < g_ns_count; i++) {
        Namespace *ns = &g_namespaces[i];
        if (!ns->active) continue;
        fprintf(stderr,
                "  [%s] ops=%llu hits=%.0f%% mem=%lluMB keys=%llu "
                "violations(mem=%llu cpu=%llu)\n",
                ns->config.name,
                (unsigned long long)ns->stats.ops_total,
                ns->stats.hit_rate * 100.0,
                (unsigned long long)(ns->stats.used_memory_bytes / 1024 / 1024),
                (unsigned long long)ns->stats.key_count,
                (unsigned long long)ns->stats.quota_violations_memory,
                (unsigned long long)ns->stats.quota_violations_cpu);
    }
    pthread_mutex_unlock(&g_lock);
}
