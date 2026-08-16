/* NexCache Compressione Automatica — Implementazione
 * LZ4 (veloce) + Zstd (ratio ottimale) + Delta (time series)
 * Copyright (c) 2026 NexCache Project — BSD License
 *
 * NOTA DIPENDENZE:
 * Per compilare questo modulo servono:
 *   - liblz4-dev  (apt-get install liblz4-dev)
 *   - libzstd-dev (apt-get install libzstd-dev)
 *
 * Alternativamente, usa le versioni header-only:
 *   - lz4.h  (single-header da https://github.com/lz4/lz4)
 *   - zstd.h (https://github.com/facebook/zstd/tree/dev/lib)
 *
 * In questa implementazione usiamo stub che simulano LZ4/Zstd
 * finché le librerie non sono disponibili.
 */

#include "auto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

/* ── Tentativo di includere le librerie reali ─────────────────
 * Se non disponibili, usiamo un'implementazione stub.
 * In produzione, rimuovi gli #ifdef e installa le librerie. */
#ifdef HAVE_LZ4
#include <lz4.h>
#include <lz4hc.h>
#endif
#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

/* ── Statistiche globali ─────────────────────────────────────── */
static CompressionStats g_stats;
static int g_initialized = 0;

/* ── Utility tempo ──────────────────────────────────────────── */
static uint64_t comp_us_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000;
}

/* ── compression_init ───────────────────────────────────────── */
int compression_init(void) {
    memset(&g_stats, 0, sizeof(g_stats));
    g_initialized = 1;
    /* Nota: mescolando #ifdef dentro fprintf si ottiene errore su clang/Apple.
     * Stampa versioni in chiamate separate. */
    fprintf(stderr, "[NexCache Compression] Init: LZ4");
#ifdef HAVE_LZ4
    fprintf(stderr, " v%d.%d.%d",
            LZ4_VERSION_MAJOR, LZ4_VERSION_MINOR, LZ4_VERSION_RELEASE);
#endif
    fprintf(stderr, " Zstd");
#ifdef HAVE_ZSTD
    fprintf(stderr, " v%s", ZSTD_versionString());
#endif
    fprintf(stderr, "\n");
    return 0;
}

/* ── compression_shutdown ───────────────────────────────────── */
void compression_shutdown(void) {
    compression_print_stats();
    g_initialized = 0;
}

/* ── Rilevamento JSON euristico ─────────────────────────────── */
static int looks_like_json(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    return (data[0] == '{' || data[0] == '[');
}

/* ── auto_select_compression ────────────────────────────────── */
CompressionType auto_select_compression(const uint8_t *data,
                                        size_t size,
                                        DataType data_type) {
    /* Troppo piccolo: overhead supera il beneficio */
    if (size < COMPRESS_THRESHOLD_MIN) return COMPRESS_NONE;

    /* Embedding vettoriali: poco comprimibili (numeri float random-ish) */
    if (data_type == DATATYPE_EMBEDDING) return COMPRESS_NONE;

    /* Dati già compressi (magic byte noti) */
    if (size >= 4) {
        /* GZIP magic */
        if (data[0] == 0x1f && data[1] == 0x8b) return COMPRESS_NONE;
        /* ZSTD magic */
        if (data[0] == 0x28 && data[1] == 0xb5 &&
            data[2] == 0x2f && data[3] == 0xfd) return COMPRESS_NONE;
        /* LZ4 magic */
        if (data[0] == 0x04 && data[1] == 0x22 &&
            data[2] == 0x4d && data[3] == 0x18) return COMPRESS_NONE;
    }

    /* Time series: delta encoding specializzato */
    if (data_type == DATATYPE_TIMESERIES) return COMPRESS_DELTA;

    /* JSON: Zstd eccellente (3-10x ratio) */
    if (data_type == DATATYPE_JSON || looks_like_json(data, size))
        return COMPRESS_ZSTD;

    /* Grandi blob: Zstd */
    if (size > COMPRESS_THRESHOLD_ZSTD) return COMPRESS_ZSTD;

    /* Oggetti medi: LZ4 per velocità */
    return COMPRESS_LZ4;
}

/* ── compress_estimate_bound ───────────────────────────────────*/
size_t compress_estimate_bound(size_t src_size, CompressionType comp_type) {
    switch (comp_type) {
#ifdef HAVE_LZ4
    case COMPRESS_LZ4:
    case COMPRESS_LZ4HC:
        return LZ4_compressBound((int)src_size) + sizeof(CompressedHeader);
#endif
#ifdef HAVE_ZSTD
    case COMPRESS_ZSTD:
        return ZSTD_compressBound(src_size) + sizeof(CompressedHeader);
#endif
    default:
        /* Stima conservativa: src_size + 12.5% + header */
        return src_size + (src_size / 8) + sizeof(CompressedHeader) + 16;
    }
}

/* ── CRC32 (IEEE 802.3) ──────────────────────────────────────── */
static uint32_t crc32_table[256];
static int crc32_table_ready = 0;

static void crc32_init_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_table_ready = 1;
}

static uint32_t crc32_checksum(const uint8_t *data, size_t len) {
    if (!crc32_table_ready) crc32_init_table();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = crc32_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ── compress_data ──────────────────────────────────────────── */
ssize_t compress_data(const uint8_t *src,
                      size_t src_size,
                      uint8_t *dst,
                      size_t dst_cap,
                      CompressionType comp_type,
                      DataType data_type) {
    if (!src || !dst || src_size == 0) return -1;
    if (dst_cap < sizeof(CompressedHeader)) return -1;

    /* Auto-selezione se richiesta */
    if (comp_type == COMPRESS_NONE) {
        comp_type = auto_select_compression(src, src_size, data_type);
    }

    if (comp_type == COMPRESS_NONE) return 0; /* Nessuna compressione */

    uint64_t t0 = comp_us_now();
    ssize_t compressed_size = -1;

    uint8_t *payload = dst + sizeof(CompressedHeader);
    size_t payload_cap = dst_cap - sizeof(CompressedHeader);

    switch (comp_type) {
#ifdef HAVE_LZ4
    case COMPRESS_LZ4:
        compressed_size = LZ4_compress_default(
            (const char *)src, (char *)payload,
            (int)src_size, (int)payload_cap);
        break;
    case COMPRESS_LZ4HC:
        compressed_size = LZ4_compress_HC(
            (const char *)src, (char *)payload,
            (int)src_size, (int)payload_cap, LZ4HC_CLEVEL_DEFAULT);
        break;
#endif
#ifdef HAVE_ZSTD
    case COMPRESS_ZSTD:
        compressed_size = (ssize_t)ZSTD_compress(
            payload, payload_cap, src, src_size, ZSTD_LEVEL_DEFAULT);
        if (ZSTD_isError(compressed_size)) compressed_size = -1;
        break;
#endif
    case COMPRESS_DELTA:
        /* Delta encoding per time series (stub: copia raw + flag) */
        if (src_size <= payload_cap) {
            memcpy(payload, src, src_size);
            compressed_size = (ssize_t)src_size;
        }
        break;
    default: {
        /* PRIMA: quando LZ4/Zstd non sono linkati (default in questa build,
         * dato che nessun HAVE_LZ4/HAVE_ZSTD è definito), compress_data
         * cadeva silenziosamente qui, faceva un memcpy e riportava
         * compressed_size==src_size — il controllo "risparmio <10%" subito
         * sotto scattava quindi SEMPRE, e compress_data ritornava 0 (nessuna
         * compressione) per ogni chiamata, senza alcun segnale a runtime
         * oltre al log a compression_init(). Un operatore che vede i log
         * "compressione abilitata" può facilmente non accorgersi che in
         * realtà non comprime mai nulla. Avvisa (una sola volta, per non
         * floodare i log sul percorso caldo) quando questo accade davvero. */
        static int warned_stub = 0;
        if (!warned_stub) {
            fprintf(stderr,
                    "[NexCache Compression] WARNING: LZ4/Zstd non linkati — "
                    "compress_data opera in modalità stub (nessuna compressione "
                    "reale verrà applicata). Compilare con HAVE_LZ4/HAVE_ZSTD per "
                    "produzione.\n");
            warned_stub = 1;
        }
        if (src_size <= payload_cap) {
            memcpy(payload, src, src_size);
            compressed_size = (ssize_t)src_size;
        }
        break;
    }
    }

    if (compressed_size <= 0) return -1;

    /* Se compressione non aiuta (< 10% risparmio), non comprimere */
    if ((size_t)compressed_size >= src_size * 9 / 10) {
        g_stats.skipped_no_benefit++;
        return 0;
    }

    /* Scrivi header */
    CompressedHeader *hdr = (CompressedHeader *)dst;
    hdr->magic = COMPRESS_MAGIC;
    hdr->original_size = (uint32_t)src_size;
    hdr->compressed_size = (uint32_t)compressed_size;
    hdr->comp_type = (uint8_t)comp_type;
    hdr->data_type = (uint8_t)data_type;
    hdr->level = ZSTD_LEVEL_DEFAULT;
    hdr->checksum = crc32_checksum(payload, (size_t)compressed_size);

    uint64_t elapsed = comp_us_now() - t0;

    /* Aggiorna statistiche */
    g_stats.total_compress_ops++;
    g_stats.bytes_before += src_size;
    g_stats.bytes_after += (size_t)compressed_size + sizeof(CompressedHeader);
    g_stats.avg_compress_us = (g_stats.avg_compress_us * 0.99) +
                              ((double)elapsed * 0.01);
    if (g_stats.bytes_before > 0) {
        g_stats.avg_ratio = (double)g_stats.bytes_after /
                            (double)g_stats.bytes_before;
    }

    return (ssize_t)(sizeof(CompressedHeader) + (size_t)compressed_size);
}

/* ── decompress_data ────────────────────────────────────────── */
ssize_t decompress_data(const uint8_t *src,
                        size_t src_size,
                        uint8_t *dst,
                        size_t dst_cap) {
    if (!src || !dst || src_size < sizeof(CompressedHeader)) return -1;

    const CompressedHeader *hdr = (const CompressedHeader *)src;

    /* Verifica magic */
    if (hdr->magic != COMPRESS_MAGIC) {
        fprintf(stderr, "[NexCache Compression] Invalid magic: 0x%08X\n",
                hdr->magic);
        return -1;
    }

    /* Verifica capacità buffer */
    if (dst_cap < hdr->original_size) {
        fprintf(stderr, "[NexCache Compression] dst too small: need %u, got %zu\n",
                hdr->original_size, dst_cap);
        return -1;
    }

    const uint8_t *payload = src + sizeof(CompressedHeader);
    size_t payload_size = src_size - sizeof(CompressedHeader);

    /* Verifica checksum */
    uint32_t cs = crc32_checksum(payload, payload_size);
    if (cs != hdr->checksum) {
        fprintf(stderr, "[NexCache Compression] Checksum mismatch: %08X != %08X\n",
                cs, hdr->checksum);
        return -1;
    }

    uint64_t t0 = comp_us_now();
    ssize_t result = -1;

    switch ((CompressionType)hdr->comp_type) {
#ifdef HAVE_LZ4
    case COMPRESS_LZ4:
    case COMPRESS_LZ4HC:
        result = LZ4_decompress_safe(
            (const char *)payload, (char *)dst,
            (int)payload_size, (int)dst_cap);
        break;
#endif
#ifdef HAVE_ZSTD
    case COMPRESS_ZSTD:
        result = (ssize_t)ZSTD_decompress(
            dst, dst_cap, payload, payload_size);
        if (ZSTD_isError(result)) result = -1;
        break;
#endif
    case COMPRESS_DELTA:
    default:
        /* Stub: copia raw */
        if (payload_size <= dst_cap) {
            memcpy(dst, payload, payload_size);
            result = (ssize_t)payload_size;
        }
        break;
    }

    if (result > 0) {
        uint64_t elapsed = comp_us_now() - t0;
        g_stats.total_decompress_ops++;
        g_stats.avg_decompress_us = (g_stats.avg_decompress_us * 0.99) +
                                    ((double)elapsed * 0.01);
    }

    return result;
}

/* ── Delta encoding per Time Series ────────────────────────── */
ssize_t delta_encode(const double *values, size_t count, uint8_t *out, size_t out_cap) {
    if (!values || !out || count == 0) return -1;

    /* Formato:
     * [uint32_t count][double first][int32_t deltas (zigzag encoded)...]
     * I delta sono in unità di 0.001 (3 decimali) */

    size_t header_size = sizeof(uint32_t) + sizeof(double);
    size_t delta_size = count * sizeof(int32_t); /* max */
    if (out_cap < header_size + delta_size) return -1;

    uint8_t *p = out;

    /* Header: count */
    *(uint32_t *)p = (uint32_t)count;
    p += sizeof(uint32_t);
    /* Primo valore raw */
    *(double *)p = values[0];
    p += sizeof(double);

    double prev = values[0];
    for (size_t i = 1; i < count; i++) {
        double delta = values[i] - prev;
        /* PRIMA: (int32_t)(delta*1000.0) è undefined behavior in C quando
         * il risultato eccede il range di int32_t (|delta| oltre
         * ~2.147e6, un salto realistico per un time series generico con
         * questo compressore) — e "d*2" nella zigzag poteva overflow una
         * seconda volta. In pratica: input con salti ampi producevano
         * output silenziosamente sbagliato/indefinito invece di un errore
         * o una gestione esplicita. Clampiamo al range rappresentabile
         * (perdita di precisione dichiarata sul singolo campione estremo,
         * ma nessun UB) invece di castare un double fuori range. */
        double scaled = delta * 1000.0; /* 3 decimali */
        const double d_limit = (double)(INT32_MAX / 2 - 1);
        if (scaled > d_limit) scaled = d_limit;
        if (scaled < -d_limit) scaled = -d_limit;
        int32_t d = (int32_t)scaled;
        uint32_t z = (d >= 0) ? (uint32_t)(d * 2) : (uint32_t)((-d * 2) - 1);
        *(uint32_t *)p = z;
        p += sizeof(uint32_t);
        prev = values[i];
    }

    return (ssize_t)(p - out);
}

/* ── Delta decoding ─────────────────────────────────────────── */
ssize_t delta_decode(const uint8_t *data, size_t data_size, double *out_values, size_t out_cap_count) {
    if (!data || !out_values || data_size < sizeof(uint32_t) + sizeof(double))
        return -1;

    const uint8_t *p = data;

    uint32_t count = *(uint32_t *)p;
    p += sizeof(uint32_t);
    if (count > out_cap_count) return -1;

    double first = *(double *)p;
    p += sizeof(double);
    out_values[0] = first;

    double prev = first;
    for (uint32_t i = 1; i < count; i++) {
        uint32_t z = *(uint32_t *)p;
        p += sizeof(uint32_t);
        /* ZigZag decode */
        int32_t d = (z & 1) ? -(int32_t)((z + 1) / 2) : (int32_t)(z / 2);
        out_values[i] = prev + (double)d / 1000.0;
        prev = out_values[i];
    }

    return (ssize_t)count;
}

/* ── Stats ──────────────────────────────────────────────────── */
CompressionStats compression_get_stats(void) {
    return g_stats;
}

void compression_print_stats(void) {
    if (!g_initialized) return;
    fprintf(stderr, "[NexCache Compression Stats]\n");
    fprintf(stderr, "  compress ops:   %llu\n",
            (unsigned long long)g_stats.total_compress_ops);
    fprintf(stderr, "  decompress ops: %llu\n",
            (unsigned long long)g_stats.total_decompress_ops);
    fprintf(stderr, "  bytes before:   %llu MB\n",
            (unsigned long long)(g_stats.bytes_before / 1024 / 1024));
    fprintf(stderr, "  bytes after:    %llu MB\n",
            (unsigned long long)(g_stats.bytes_after / 1024 / 1024));
    fprintf(stderr, "  avg ratio:      %.2f (lower=better)\n", g_stats.avg_ratio);
    fprintf(stderr, "  avg compress:   %.1f µs\n", g_stats.avg_compress_us);
    fprintf(stderr, "  avg decompress: %.1f µs\n", g_stats.avg_decompress_us);
    fprintf(stderr, "  skipped (small):%llu\n",
            (unsigned long long)g_stats.skipped_too_small);
    fprintf(stderr, "  skipped (no benefit): %llu\n",
            (unsigned long long)g_stats.skipped_no_benefit);
}
