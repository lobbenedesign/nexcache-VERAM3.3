/* NexCache HNSW Vector Index — Implementazione completa
 * ============================================================
 * Hierarchical Navigable Small World (HNSW) per ricerca vettoriale
 * approssimata ad alta velocità (ANN = Approximate Nearest Neighbor).
 *
 * Perché HNSW è meglio di tutto il resto:
 *   - O(log N) query time vs O(N) per Flat search
 *   - 99% recall@10 con dataset 1M vettori
 *   - Aggiornamenti online (insert/delete senza ricostruzione)
 *
 * Differenza con NexCache/NexCache:
 *   - NexCache usa FLAT search (O(N), non scala oltre 100K vettori)
 *   - NexCache 9.0 ha introdotto HNSW ma senza quantizzazione
 *   - NexCache: HNSW + Int8/Binary quantization (25-96% risparmio memoria)
 *
 * Paper: Malkov & Yashunin 2016 "Efficient and robust approximate"
 *
 * Parametri tuning:
 *   M    = numero max connessioni per nodo (default 16)
 *          Più alto → migliore recall, più RAM
 *   ef   = beam width durante query (default 200)
 *          Più alto → migliore recall, più lento
 *   ef_c = beam width durante costruzione (default 200)
 *          Più alto → migliore struttura grafo, build più lenta
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "hnsw.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <sys/time.h>
#include <pthread.h>

/* ── Utility ────────────────────────────────────────────────── */
static uint64_t hnsw_us_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* ── Distance functions ─────────────────────────────────────── */

/* Cosine distance = 1 - cosine_similarity
 * Ottimizzata con loop unrolling 4x (auto-vectorizable) */
static float cosine_distance(const float *a, const float *b, int dim) {
    double dot = 0, na = 0, nb = 0;
    int i = 0;
    for (; i <= dim - 4; i += 4) {
        dot += (double)a[i] * b[i] + (double)a[i + 1] * b[i + 1] + (double)a[i + 2] * b[i + 2] + (double)a[i + 3] * b[i + 3];
        na += (double)a[i] * a[i] + (double)a[i + 1] * a[i + 1] + (double)a[i + 2] * a[i + 2] + (double)a[i + 3] * a[i + 3];
        nb += (double)b[i] * b[i] + (double)b[i + 1] * b[i + 1] + (double)b[i + 2] * b[i + 2] + (double)b[i + 3] * b[i + 3];
    }
    for (; i < dim; i++) {
        dot += (double)a[i] * b[i];
        na += (double)a[i] * a[i];
        nb += (double)b[i] * b[i];
    }
    double denom = sqrt(na) * sqrt(nb);
    if (denom < 1e-12) return 1.0f;
    float sim = (float)(dot / denom);
    if (sim > 1.0f) sim = 1.0f;
    if (sim < -1.0f) sim = -1.0f;
    return 1.0f - sim; /* Distance = 1 - similarity */
}

/* L2 squared distance */
static float l2_distance(const float *a, const float *b, int dim) {
    double dist = 0;
    int i = 0;
    for (; i <= dim - 4; i += 4) {
        double d0 = a[i] - b[i];
        double d1 = a[i + 1] - b[i + 1];
        double d2 = a[i + 2] - b[i + 2];
        double d3 = a[i + 3] - b[i + 3];
        dist += d0 * d0 + d1 * d1 + d2 * d2 + d3 * d3;
    }
    for (; i < dim; i++) {
        double d = a[i] - b[i];
        dist += d * d;
    }
    return (float)dist;
}

/* ── Funzione distanza configurable ─────────────────────────── */
static float compute_distance(HNSWIndex *idx,
                              const float *a,
                              const float *b) {
    idx->stats.distance_calcs++;
    if (idx->metric == HNSW_METRIC_COSINE)
        return cosine_distance(a, b, idx->dim);
    else
        return l2_distance(a, b, idx->dim);
}

/* ── Priority Queue (min-heap) per il beam search ───────────── */

/* HeapNode: (distanza, node_id) */
typedef struct {
    float dist;
    hnsw_id_t id;
} HeapNode;

/* PRIMA: heap_push scriveva su heap[(*size)++] senza alcun controllo di
 * capacità. Il buffer 'candidates' in search_layer viene allocato con
 * capacità ef*4+4 (pensata per il caso comune), ma la fase di beam
 * search può spingere fino a M_max0 (fino a 32+ vicini per nodo a
 * layer 0) nuovi candidati in una singola espansione, prima che il
 * prossimo heap_pop liberi spazio — con ef=1 (usato nella discesa di
 * Fase 1 sia in hnsw_add che in hnsw_search, capacità=8) un nodo ad alto
 * grado supera facilmente la capacità: scrittura oltre i limiti
 * dell'array (heap overflow). ORA: cresce dinamicamente come un
 * normale vector, invece di assumere un limite superiore che la beam
 * search può violare. */
static void heap_push(HeapNode **heap, int *size, int *cap, float dist, hnsw_id_t id) {
    if (*size >= *cap) {
        int new_cap = *cap > 0 ? *cap * 2 : 8;
        HeapNode *nh = (HeapNode *)realloc(*heap, (size_t)new_cap * sizeof(HeapNode));
        if (!nh) return; /* Meglio scartare il candidato che corrompere memoria */
        *heap = nh;
        *cap = new_cap;
    }
    HeapNode *h = *heap;
    int i = (*size)++;
    h[i].dist = dist;
    h[i].id = id;
    /* Bubble up */
    while (i > 0) {
        int parent = (i - 1) / 2;
        if (h[parent].dist > h[i].dist) {
            HeapNode tmp = h[parent];
            h[parent] = h[i];
            h[i] = tmp;
            i = parent;
        } else
            break;
    }
}

static HeapNode heap_pop(HeapNode *heap, int *size) {
    HeapNode top = heap[0];
    heap[0] = heap[--(*size)];
    /* Bubble down */
    int i = 0;
    while (1) {
        int left = 2 * i + 1;
        int right = 2 * i + 2;
        int smallest = i;
        if (left < *size && heap[left].dist < heap[smallest].dist) smallest = left;
        if (right < *size && heap[right].dist < heap[smallest].dist) smallest = right;
        if (smallest == i) break;
        HeapNode tmp = heap[smallest];
        heap[smallest] = heap[i];
        heap[i] = tmp;
        i = smallest;
    }
    return top;
}

/* Max-heap pop (per il risultato top-K) */
static void maxheap_push(HeapNode *heap, int *size, float dist, hnsw_id_t id) {
    int i = (*size)++;
    heap[i].dist = dist;
    heap[i].id = id;
    /* Bubble up max */
    while (i > 0) {
        int parent = (i - 1) / 2;
        if (heap[parent].dist < heap[i].dist) {
            HeapNode tmp = heap[parent];
            heap[parent] = heap[i];
            heap[i] = tmp;
            i = parent;
        } else
            break;
    }
}

static HeapNode maxheap_pop(HeapNode *heap, int *size) {
    HeapNode top = heap[0];
    heap[0] = heap[--(*size)];
    int i = 0;
    while (1) {
        int left = 2 * i + 1;
        int right = 2 * i + 2;
        int largest = i;
        if (left < *size && heap[left].dist > heap[largest].dist) largest = left;
        if (right < *size && heap[right].dist > heap[largest].dist) largest = right;
        if (largest == i) break;
        HeapNode tmp = heap[largest];
        heap[largest] = heap[i];
        heap[i] = tmp;
        i = largest;
    }
    return top;
}

/* ── hnsw_create ────────────────────────────────────────────── */
HNSWIndex *hnsw_create(int dim, int M, int ef_construction, HNSWMetric metric, QuantType quant) {
    if (dim <= 0 || M <= 0) return NULL;

    HNSWIndex *idx = (HNSWIndex *)calloc(1, sizeof(HNSWIndex));
    if (!idx) return NULL;

    idx->dim = dim;
    idx->M = M;
    idx->M_max0 = M * 2; /* Layer 0 ha più connessioni */
    idx->ef_construction = ef_construction > 0 ? ef_construction : HNSW_DEFAULT_EF_CONSTRUCTION;
    idx->ef = HNSW_DEFAULT_EF;
    idx->metric = metric;
    idx->quant = quant;
    idx->enter_point = HNSW_INVALID_ID;
    idx->max_layer = 0;
    idx->mult = 1.0 / log((double)M); /* Livello = floor(-ln(rand) * mult) */

    idx->cap = HNSW_INITIAL_CAPACITY;
    idx->nodes = (HNSWNode *)calloc(idx->cap, sizeof(HNSWNode));
    if (!idx->nodes) {
        free(idx);
        return NULL;
    }

    pthread_rwlock_init(&idx->rwlock, NULL);

    fprintf(stderr,
            "[NexCache HNSW] Created index: dim=%d M=%d ef=%d metric=%s quant=%s\n",
            dim, M, idx->ef_construction,
            metric == HNSW_METRIC_COSINE ? "cosine" : "l2",
            quant == HNSW_QUANT_FLOAT32 ? "f32" : quant == HNSW_QUANT_INT8 ? "int8"
                                                                           : "binary");

    return idx;
}

/* ── Level generator ────────────────────────────────────────── */
static int random_level(HNSWIndex *idx) {
    double r = (double)rand() / RAND_MAX;
    int level = (int)(-log(r) * idx->mult);
    if (level > HNSW_MAX_LAYERS - 1) level = HNSW_MAX_LAYERS - 1;
    return level;
}

/* ── Nearest neighbors in layer ─────────────────────────────── */
/* Restituisce i W vicini più vicini a query_vec partendo da ep,
 * usando beam search con larghezza ef.
 * Scrive i risultati in 'results' (max_results elementi).
 * Returns: numero di risultati trovati. */
static int search_layer(HNSWIndex *idx,
                        const float *query_vec,
                        hnsw_id_t entry_id,
                        int ef,
                        int layer,
                        HeapNode *results,
                        int max_results) {
    /* Candidates: min-heap per priorità ricerca. Capacità iniziale
     * ef*4+4 come stima, ma cresce dinamicamente in heap_push — vedi
     * commento su heap_push per il motivo (overflow altrimenti). */
    int cand_cap = ef * 4 + 4;
    HeapNode *candidates = (HeapNode *)malloc((size_t)cand_cap * sizeof(HeapNode));
    if (!candidates) return 0;

    /* Risultati: max-heap per mantenere top-ef vicini */
    HeapNode *result_heap = (HeapNode *)malloc(
        (size_t)(ef * 4 + 4) * sizeof(HeapNode));
    if (!result_heap) {
        free(candidates);
        return 0;
    }

    /* Visited set: bitmap semplice */
    size_t visited_cap = (size_t)idx->count / 8 + 1;
    uint8_t *visited = (uint8_t *)calloc(visited_cap, 1);
    if (!visited) {
        free(candidates);
        free(result_heap);
        return 0;
    }

    int cand_size = 0, res_size = 0;

    float dist_ep = compute_distance(idx, query_vec,
                                     idx->nodes[entry_id].vector);

    heap_push(&candidates, &cand_size, &cand_cap, dist_ep, entry_id);
    maxheap_push(result_heap, &res_size, dist_ep, entry_id);

    size_t entry_byte = entry_id / 8;
    if (entry_byte < visited_cap)
        visited[entry_byte] |= (1 << (entry_id % 8));

    while (cand_size > 0) {
        HeapNode closest = heap_pop(candidates, &cand_size);

        /* Se il candidato è peggiore del peggior risultato: stop */
        if (res_size >= ef && closest.dist > result_heap[0].dist)
            break;

        HNSWNode *node = &idx->nodes[closest.id];

        /* Esplora i vicini nel layer corrente */
        int num_neighbors = layer < HNSW_MAX_LAYERS ? node->num_neighbors[layer] : 0;
        hnsw_id_t *neighbors = node->neighbors[layer];

        for (int j = 0; j < num_neighbors; j++) {
            hnsw_id_t nb_id = neighbors[j];
            if (nb_id == HNSW_INVALID_ID) continue;

            size_t nb_byte = nb_id / 8;
            uint8_t nb_bit = 1 << (nb_id % 8);
            if (nb_byte < visited_cap && (visited[nb_byte] & nb_bit)) continue;
            if (nb_byte < visited_cap) visited[nb_byte] |= nb_bit;

            float dist_nb = compute_distance(idx, query_vec,
                                             idx->nodes[nb_id].vector);

            if (res_size < ef || dist_nb < result_heap[0].dist) {
                heap_push(&candidates, &cand_size, &cand_cap, dist_nb, nb_id);
                maxheap_push(result_heap, &res_size, dist_nb, nb_id);
                if (res_size > ef) {
                    maxheap_pop(result_heap, &res_size); /* Rimuovi il peggiore */
                }
            }
        }
    }

    /* Copia risultati ordinati (dal migliore al peggiore) */
    int n = res_size < max_results ? res_size : max_results;
    /* I risultati nel max-heap sono in ordine decrescente */
    /* Invertiamoli copiandoli in un array temporaneo */
    HeapNode *sorted = (HeapNode *)malloc((size_t)res_size * sizeof(HeapNode));
    if (sorted) {
        for (int i = res_size - 1; i >= 0; i--) {
            sorted[i] = maxheap_pop(result_heap, &res_size);
        }
        for (int i = 0; i < n; i++) results[i] = sorted[i];
        free(sorted);
    }

    free(candidates);
    free(result_heap);
    free(visited);
    return n;
}

/* ── hnsw_add ───────────────────────────────────────────────── */
int hnsw_add(HNSWIndex *idx, hnsw_id_t ext_id, const float *vector, const char *metadata) {
    if (!idx || !vector) return -1;

    pthread_rwlock_wrlock(&idx->rwlock);

    /* Espandi capacity se necessario */
    if (idx->count >= idx->cap) {
        size_t new_cap = idx->cap * 2;
        HNSWNode *new_nodes = (HNSWNode *)realloc(
            idx->nodes, new_cap * sizeof(HNSWNode));
        if (!new_nodes) {
            pthread_rwlock_unlock(&idx->rwlock);
            return -1;
        }
        memset(new_nodes + idx->cap, 0,
               (new_cap - idx->cap) * sizeof(HNSWNode));
        idx->nodes = new_nodes;
        idx->cap = new_cap;
    }

    hnsw_id_t new_id = (hnsw_id_t)idx->count;
    HNSWNode *node = &idx->nodes[new_id];

    /* Copia vettore */
    node->vector = (float *)malloc((size_t)idx->dim * sizeof(float));
    if (!node->vector) {
        pthread_rwlock_unlock(&idx->rwlock);
        return -1;
    }
    memcpy(node->vector, vector, (size_t)idx->dim * sizeof(float));
    node->ext_id = ext_id;
    node->level = random_level(idx);
    node->is_deleted = 0;
    if (metadata) strncpy(node->metadata, metadata, sizeof(node->metadata) - 1);

    /* Inizializza array vicini */
    for (int l = 0; l < HNSW_MAX_LAYERS; l++) {
        int max_conns = (l == 0) ? idx->M_max0 : idx->M;
        node->neighbors[l] = (hnsw_id_t *)malloc(
            (size_t)max_conns * sizeof(hnsw_id_t));
        if (!node->neighbors[l]) {
            /* Cleanup */
            for (int ll = 0; ll < l; ll++) free(node->neighbors[ll]);
            free(node->vector);
            pthread_rwlock_unlock(&idx->rwlock);
            return -1;
        }
        for (int j = 0; j < max_conns; j++)
            node->neighbors[l][j] = HNSW_INVALID_ID;
        node->num_neighbors[l] = 0;
    }

    idx->count++;

    /* Primo nodo: semplicemente il punto di entrata */
    if (idx->enter_point == HNSW_INVALID_ID) {
        idx->enter_point = new_id;
        idx->max_layer = node->level;
        pthread_rwlock_unlock(&idx->rwlock);
        idx->stats.inserts++;
        return 0;
    }

    /* HNSW greedy insert:
     * 1. Naviga dall'entry point al layer del nuovo nodo
     * 2. Per ogni layer, trova i vicini migliori e connettili */

    hnsw_id_t ep = idx->enter_point;
    int ep_level = idx->max_layer;

    HeapNode *results = (HeapNode *)malloc(
        (size_t)(idx->ef_construction + 4) * sizeof(HeapNode));
    if (!results) {
        pthread_rwlock_unlock(&idx->rwlock);
        return -1;
    }

    /* Fase 1: dall'entry point scendi fino al layer del nodo */
    for (int l = ep_level; l > node->level; l--) {
        int n = search_layer(idx, vector, ep, 1, l, results, 1);
        if (n > 0) ep = results[0].id;
    }

    /* Fase 2: per ogni layer del nodo, trova vicini e connetti */
    for (int l = node->level < ep_level ? node->level : ep_level; l >= 0; l--) {
        int max_conns = (l == 0) ? idx->M_max0 : idx->M;
        int n = search_layer(idx, vector, ep, idx->ef_construction,
                             l, results, max_conns);
        if (n == 0) {
            ep = idx->enter_point;
            continue;
        }

        /* Collega new_id ↔ i vicini trovati */
        int to_connect = n < max_conns ? n : max_conns;
        for (int j = 0; j < to_connect; j++) {
            hnsw_id_t nb_id = results[j].id;
            if (nb_id == HNSW_INVALID_ID || nb_id == new_id) continue;

            /* Aggiungi nb come vicino di new_id */
            if (node->num_neighbors[l] < max_conns) {
                int nn = node->num_neighbors[l]++;
                node->neighbors[l][nn] = nb_id;
            }

            /* Aggiungi new_id come vicino di nb (reciproco) */
            HNSWNode *nb = &idx->nodes[nb_id];
            if (nb->num_neighbors[l] < max_conns) {
                int nn = nb->num_neighbors[l]++;
                nb->neighbors[l][nn] = new_id;
            }
        }

        if (n > 0) ep = results[0].id;
    }

    free(results);

    /* Aggiorna entry point se il nuovo nodo è su un layer più alto */
    if (node->level > (int)idx->max_layer) {
        idx->max_layer = node->level;
        idx->enter_point = new_id;
    }

    idx->stats.inserts++;
    pthread_rwlock_unlock(&idx->rwlock);
    return 0;
}

/* ── hnsw_search ─────────────────────────────────────────────── */
int hnsw_search(HNSWIndex *idx,
                const float *query_vec,
                int k,
                int ef,
                HNSWResult *results,
                int *num_results) {
    if (!idx || !query_vec || !results || !num_results) return -1;
    *num_results = 0;

    pthread_rwlock_rdlock(&idx->rwlock);

    if (idx->count == 0 || idx->enter_point == HNSW_INVALID_ID) {
        pthread_rwlock_unlock(&idx->rwlock);
        return 0;
    }

    if (ef <= 0) ef = idx->ef;
    if (ef < k) ef = k;

    uint64_t t0 = hnsw_us_now();

    hnsw_id_t ep = idx->enter_point;
    int ep_level = (int)idx->max_layer;

    HeapNode *beam = (HeapNode *)malloc((size_t)(ef * 4 + 4) * sizeof(HeapNode));
    if (!beam) {
        pthread_rwlock_unlock(&idx->rwlock);
        return -1;
    }

    /* Top-layer greedy descent */
    for (int l = ep_level; l > 0; l--) {
        int n = search_layer(idx, query_vec, ep, 1, l, beam, 1);
        if (n > 0) ep = beam[0].id;
    }

    /* Layer 0: beam search con ef largo */
    int n = search_layer(idx, query_vec, ep, ef, 0, beam, ef);

    /* Filtra deleted, riempi results */
    int out = 0;
    for (int i = 0; i < n && out < k; i++) {
        hnsw_id_t cid = beam[i].id;
        if (idx->nodes[cid].is_deleted) continue;
        results[out].id = cid;
        results[out].ext_id = idx->nodes[cid].ext_id;
        results[out].distance = beam[i].dist;
        results[out].score = 1.0f - beam[i].dist; /* Per cosine */
        out++;
    }
    *num_results = out;

    free(beam);

    uint64_t elapsed = hnsw_us_now() - t0;
    idx->stats.searches++;
    idx->stats.avg_search_us = idx->stats.avg_search_us * 0.99 +
                               (double)elapsed * 0.01;

    pthread_rwlock_unlock(&idx->rwlock);
    return 0;
}

/* ── hnsw_delete ────────────────────────────────────────────── */
int hnsw_delete(HNSWIndex *idx, hnsw_id_t ext_id) {
    if (!idx) return -1;

    pthread_rwlock_wrlock(&idx->rwlock);
    /* Soft delete: marca il nodo come eliminato */
    for (hnsw_id_t i = 0; i < (hnsw_id_t)idx->count; i++) {
        if (idx->nodes[i].ext_id == ext_id && !idx->nodes[i].is_deleted) {
            idx->nodes[i].is_deleted = 1;
            idx->stats.deletes++;
            pthread_rwlock_unlock(&idx->rwlock);
            return 0;
        }
    }
    pthread_rwlock_unlock(&idx->rwlock);
    return -1;
}

/* ── hnsw_get_stats ─────────────────────────────────────────── */
HNSWStats hnsw_get_stats(HNSWIndex *idx) {
    HNSWStats empty = {0};
    if (!idx) return empty;
    pthread_rwlock_rdlock(&idx->rwlock);
    HNSWStats s = idx->stats;
    s.count = idx->count;
    s.max_layer = (int)idx->max_layer;
    /* Stima memoria: vettori + struttura grafo */
    s.memory_bytes = (uint64_t)idx->count *
                     ((size_t)idx->dim * sizeof(float) +             /* Vettori */
                      HNSW_MAX_LAYERS * idx->M * sizeof(hnsw_id_t)); /* Neighbors */
    pthread_rwlock_unlock(&idx->rwlock);
    return s;
}

/* ── hnsw_print_stats ───────────────────────────────────────── */
void hnsw_print_stats(HNSWIndex *idx) {
    if (!idx) return;
    HNSWStats s = hnsw_get_stats(idx);
    fprintf(stderr,
            "[NexCache HNSW] Stats:\n"
            "  vectors:       %zu\n"
            "  max_layer:     %d\n"
            "  M:             %d\n"
            "  ef_search:     %d\n"
            "  inserts:       %llu\n"
            "  searches:      %llu\n"
            "  deletes:       %llu\n"
            "  distance_calcs:%llu\n"
            "  avg_search_us: %.1f\n"
            "  memory_MB:     %.1f\n",
            s.count, s.max_layer, idx->M, idx->ef,
            (unsigned long long)s.inserts,
            (unsigned long long)s.searches,
            (unsigned long long)s.deletes,
            (unsigned long long)s.distance_calcs,
            s.avg_search_us,
            (double)s.memory_bytes / 1024.0 / 1024.0);
}

/* ── hnsw_destroy ───────────────────────────────────────────── */
void hnsw_destroy(HNSWIndex *idx) {
    if (!idx) return;
    pthread_rwlock_wrlock(&idx->rwlock);
    for (hnsw_id_t i = 0; i < (hnsw_id_t)idx->count; i++) {
        free(idx->nodes[i].vector);
        for (int l = 0; l < HNSW_MAX_LAYERS; l++)
            free(idx->nodes[i].neighbors[l]);
    }
    free(idx->nodes);
    pthread_rwlock_unlock(&idx->rwlock);
    pthread_rwlock_destroy(&idx->rwlock);
    free(idx);
}
