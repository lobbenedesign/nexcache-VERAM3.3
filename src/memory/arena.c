/* NexCache Arena Allocator — Implementazione
 * ============================================================
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "arena.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>

/* ── Arena globale ──────────────────────────────────────────── */
Arena *g_nexcache_arena = NULL;

/* ── Funzioni interne ───────────────────────────────────────── */

/**
 * arena_block_create - Alloca un nuovo blocco con mmap().
 * Usiamo mmap() invece di malloc() per:
 *  1. Controllo esplicito delle pagine (possiamo usare madvise/mlock)
 *  2. Allineamento garantito a pagina (4KB o 2MB huge pages)
 *  3. Zero dipendenza dall'heap C
 */
static ArenaBlock *arena_block_create(size_t size) {
    /* Allinea la dimensione a multipli di pagina (4096) */
    size_t page_size = (size_t)getpagesize();
    size_t aligned_sz = (size + page_size - 1) & ~(page_size - 1);

    /* Alloca il descrittore del blocco */
    ArenaBlock *block = (ArenaBlock *)malloc(sizeof(ArenaBlock));
    if (!block) return NULL;

    /* Alloca la memoria con mmap — MAP_ANONYMOUS = non legato a file */
    void *mem = mmap(NULL, aligned_sz,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    if (mem == MAP_FAILED) {
        free(block);
        return NULL;
    }

    block->magic = ARENA_MAGIC;
    block->base = (uint8_t *)mem;
    block->size = aligned_sz;
    block->used = 0;
    block->peak = 0;
    block->next = NULL;
    block->prev = NULL;
    return block;
}

/**
 * arena_block_destroy - Libera un blocco con munmap().
 */
static void arena_block_destroy(ArenaBlock *block) {
    if (!block) return;
    assert(block->magic == ARENA_MAGIC);
    block->magic = 0; /* Invalida il blocco */
    munmap(block->base, block->size);
    free(block);
}

/**
 * _get_time_ns - Timestamp ad alta risoluzione in nanosecondi.
 */
static inline uint64_t _get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── API pubblica ───────────────────────────────────────────── */

Arena *arena_create(size_t block_size, const char *name, int thread_local_mode) {
    if (block_size == 0) block_size = ARENA_DEFAULT_SIZE;

    Arena *arena = (Arena *)malloc(sizeof(Arena));
    if (!arena) return NULL;

    memset(arena, 0, sizeof(Arena));
    arena->default_block_sz = block_size;
    arena->is_thread_local = thread_local_mode;

    if (name) {
        strncpy(arena->name, name, sizeof(arena->name) - 1);
    } else {
        strncpy(arena->name, "unnamed", sizeof(arena->name) - 1);
    }

    /* Inizializza il mutex (usato solo se !thread_local_mode) */
    if (!thread_local_mode) {
        pthread_mutex_init(&arena->lock, NULL);
    }

    /* Crea il primo blocco */
    ArenaBlock *first = arena_block_create(block_size);
    if (!first) {
        free(arena);
        return NULL;
    }

    arena->current = first;
    arena->head = first;
    arena->stats.block_count = 1;
    return arena;
}

void *arena_alloc_aligned(Arena *arena, size_t size, size_t alignment) {
    if (!arena || size == 0) return NULL;

    /* alignment deve essere potenza di 2 */
    if (alignment == 0) alignment = 8;
    assert((alignment & (alignment - 1)) == 0);

    /* PRIMA: clock_gettime() veniva chiamato DUE VOLTE per ogni singola
     * allocazione (qui e dopo aver allocato) per aggiornare la EWMA
     * avg_alloc_ns — un bump allocator fa poche operazioni intere e
     * dovrebbe costare pochi nanosecondi, ma due syscall/vDSO-call di
     * timing per chiamata dominavano completamente quel costo (misurato:
     * 1M allocazioni da 64 byte arrivavano a 62ns/op contro i ~27ns/op di
     * malloc — l'allocatore risultava "più lento di malloc" perché
     * l'istrumentazione stessa era il collo di bottiglia, non il bump
     * pointer). ORA: il timing è campionato (1 chiamata su
     * ARENA_TIMING_SAMPLE_EVERY) — la EWMA resta statisticamente
     * rappresentativa ma il costo del timing scende di due ordini di
     * grandezza sul percorso caldo. */
#define ARENA_TIMING_SAMPLE_EVERY 64
    int do_timing = (arena->stats.total_allocs % ARENA_TIMING_SAMPLE_EVERY) == 0;
    uint64_t t_start = do_timing ? _get_time_ns() : 0;

    if (!arena->is_thread_local)
        pthread_mutex_lock(&arena->lock);

    ArenaBlock *block = arena->current;
    assert(block && block->magic == ARENA_MAGIC);

    /* Calcola il bump pointer allineato */
    uintptr_t current_ptr = (uintptr_t)(block->base + block->used);
    uintptr_t aligned_ptr = (current_ptr + alignment - 1) & ~(alignment - 1);
    size_t padding = aligned_ptr - current_ptr;
    size_t total_need = padding + size;

    void *result = NULL;

    if (block->used + total_need <= block->size) {
        /* Caso comune: spazio disponibile nel blocco corrente */
        result = (void *)aligned_ptr;
        block->used += total_need;
        if (block->used > block->peak) block->peak = block->used;

        arena->stats.wasted_bytes += padding;
    } else {
        /* Blocco pieno: alloca un nuovo blocco */
        size_t new_size = arena->default_block_sz * ARENA_GROWTH_FACTOR;
        if (new_size < size + alignment) new_size = size + alignment + 4096;

        ArenaBlock *new_block = arena_block_create(new_size);
        if (new_block) {
            /* Inserisci il nuovo blocco come current */
            new_block->prev = block;
            block->next = new_block;
            arena->current = new_block;
            arena->stats.block_count++;

            /* Alloca nel nuovo blocco */
            uintptr_t np = (uintptr_t)(new_block->base);
            uintptr_t ap = (np + alignment - 1) & ~(alignment - 1);
            size_t pd = ap - np;
            result = (void *)ap;
            new_block->used = pd + size;
            if (new_block->used > new_block->peak) new_block->peak = new_block->used;
            arena->stats.wasted_bytes += pd;
        }
    }

    if (result) {
        arena->stats.total_allocs++;
        arena->stats.total_bytes += size;

        /* Aggiorna media latenza con exponential moving average — solo
         * sui campioni cronometrati (vedi do_timing sopra). */
        if (do_timing) {
            uint64_t elapsed = _get_time_ns() - t_start;
            double alpha = 0.1;
            arena->stats.avg_alloc_ns =
                arena->stats.avg_alloc_ns * (1.0 - alpha) + (double)elapsed * alpha;
        }
    }

    if (!arena->is_thread_local)
        pthread_mutex_unlock(&arena->lock);

    return result;
}

void *arena_alloc(Arena *arena, size_t size) {
    /* Allineamento naturale per la maggior parte degli oggetti */
    size_t alignment = (size >= 8) ? 8 : size;
    /* Forza potenza di 2 */
    size_t al = 1;
    while (al < alignment) al <<= 1;
    return arena_alloc_aligned(arena, size, al);
}

void *arena_alloc_zeroed(Arena *arena, size_t size) {
    void *ptr = arena_alloc(arena, size);
    if (ptr) memset(ptr, 0, size);
    return ptr;
}

char *arena_strdup(Arena *arena, const char *str) {
    if (!str) return NULL;
    size_t len = strlen(str) + 1;
    char *copy = (char *)arena_alloc(arena, len);
    if (copy) memcpy(copy, str, len);
    return copy;
}

char *arena_strndup(Arena *arena, const char *str, size_t n) {
    if (!str) return NULL;
    size_t len = strnlen(str, n);
    char *copy = (char *)arena_alloc(arena, len + 1);
    if (copy) {
        memcpy(copy, str, len);
        copy[len] = '\0';
    }
    return copy;
}

void arena_reset(Arena *arena) {
    if (!arena) return;

    if (!arena->is_thread_local)
        pthread_mutex_lock(&arena->lock);

    /* Torna al primo blocco e azzera tutti i cursori */
    ArenaBlock *block = arena->head;
    while (block) {
        block->used = 0;
        block = block->next;
    }
    arena->current = arena->head;
    arena->stats.reset_count++;

    if (!arena->is_thread_local)
        pthread_mutex_unlock(&arena->lock);
}

void arena_destroy(Arena *arena) {
    if (!arena) return;

    ArenaBlock *block = arena->head;
    while (block) {
        ArenaBlock *next = block->next;
        arena_block_destroy(block);
        block = next;
    }

    if (!arena->is_thread_local)
        pthread_mutex_destroy(&arena->lock);

    free(arena);
}

size_t arena_used(Arena *arena) {
    if (!arena) return 0;
    size_t total = 0;
    ArenaBlock *b = arena->head;
    while (b) {
        total += b->used;
        b = b->next;
    }
    return total;
}

size_t arena_capacity(Arena *arena) {
    if (!arena) return 0;
    size_t total = 0;
    ArenaBlock *b = arena->head;
    while (b) {
        total += b->size;
        b = b->next;
    }
    return total;
}

size_t arena_wasted(Arena *arena) {
    if (!arena) return 0;
    return arena->stats.wasted_bytes;
}

ArenaStats arena_get_stats(Arena *arena) {
    ArenaStats s = {0};
    if (arena) {
        if (!arena->is_thread_local) pthread_mutex_lock(&arena->lock);
        s = arena->stats;
        if (!arena->is_thread_local) pthread_mutex_unlock(&arena->lock);
    }
    return s;
}

void arena_print_stats(Arena *arena) {
    if (!arena) return;
    ArenaStats s = arena_get_stats(arena);
    fprintf(stderr,
            "[NexCache Arena '%s'] allocs=%llu bytes=%llu wasted=%llu "
            "blocks=%llu resets=%llu avg_alloc=%.1fns\n",
            arena->name,
            (unsigned long long)s.total_allocs,
            (unsigned long long)s.total_bytes,
            (unsigned long long)s.wasted_bytes,
            (unsigned long long)s.block_count,
            (unsigned long long)s.reset_count,
            s.avg_alloc_ns);
}

int nexcache_arena_init(void) {
    g_nexcache_arena = arena_create(ARENA_LARGE_SIZE, "global", 0);
    return g_nexcache_arena ? 0 : -1;
}

void nexcache_arena_shutdown(void) {
    if (g_nexcache_arena) {
        arena_print_stats(g_nexcache_arena);
        arena_destroy(g_nexcache_arena);
        g_nexcache_arena = NULL;
    }
}
