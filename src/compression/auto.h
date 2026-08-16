/* NexCache Compressione Automatica — MODULO 6
 * ============================================================
 * Compressione trasparente per il client.
 * Il bit TPTR_FLAG_COMPRESSED nel tagged pointer indica
 * se il dato è compresso.
 *
 * Regole di selezione automatica:
 *   < 64 bytes   → NESSUNA compressione (overhead > beneficio)
 *   64-4096 bytes → LZ4 (velocità massima, ~500 MB/s decompress)
 *   > 4096 bytes  → Zstandard livello 3 (bilanciamento)
 *   JSON          → Zstandard (altamente comprimibile, 5-10x)
 *   Time Series   → Delta + ZigZag encoding (specializzato numeri)
 *
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#ifndef NEXCACHE_COMPRESSION_H
#define NEXCACHE_COMPRESSION_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* ── Tipi di compressione ───────────────────────────────────── */
typedef enum CompressionType {
    COMPRESS_NONE = 0,  /* Nessuna compressione */
    COMPRESS_LZ4 = 1,   /* LZ4 — velocissima, ratio medio */
    COMPRESS_ZSTD = 2,  /* Zstandard — ottimo ratio, veloce */
    COMPRESS_DELTA = 3, /* Delta encoding — per time series */
    COMPRESS_LZ4HC = 4, /* LZ4 high compression — più lenta ma migliore ratio */
} CompressionType;

/* Livelli Zstandard: 1=veloce 3=bilanciato 9=massimo 22=ultra */
#define ZSTD_LEVEL_FAST 1
#define ZSTD_LEVEL_DEFAULT 3
#define ZSTD_LEVEL_MAX 9

/* Soglie per selezione automatica */
#define COMPRESS_THRESHOLD_MIN 64    /* < 64 byte: non comprimere */
#define COMPRESS_THRESHOLD_LZ4 4096  /* < 4KB: usa LZ4 */
#define COMPRESS_THRESHOLD_ZSTD 4096 /* >= 4KB: usa Zstd */

/* ── Tipo di dato (hint per la selezione algoritmo) ─────────── */
typedef enum DataType {
    DATATYPE_GENERIC = 0,
    DATATYPE_STRING = 1,
    DATATYPE_JSON = 2,
    DATATYPE_TIMESERIES = 3,
    DATATYPE_BINARY = 4,
    DATATYPE_EMBEDDING = 5, /* Vettori float — poco comprimibili */
} DataType;

/* ── Header di un dato compresso (19 byte) ────────────────────
 * PRIMA: checksum era un XOR a 1 byte — ~1/256 di probabilità di
 * accettare silenziosamente un payload corrotto in decompress_data, e
 * trivialmente aggirabile da un flip di due byte con la stessa parità
 * nella stessa posizione. Sufficiente come sanity check interno, non
 * come integrity check se questo buffer attraversa un confine non
 * fidato (replica, tiering su disco). Il campo è stato allargato a
 * CRC32 (nessun dato reale è mai stato persistito con questo formato,
 * dato che il modulo non è ancora collegato a un command path). */
typedef struct __attribute__((packed)) CompressedHeader {
    uint32_t magic;           /* 0x4E584348 = "NXCH" */
    uint32_t original_size;   /* Dimesione dati originali */
    uint32_t compressed_size; /* Dimensione compressa */
    uint8_t comp_type;        /* CompressionType */
    uint8_t data_type;        /* DataType (hint) */
    uint8_t level;            /* Livello compressione */
    uint32_t checksum;        /* CRC32 dei byte dati */
} CompressedHeader;

#define COMPRESS_MAGIC 0x4E584348U /* "NXCH" */

/* ── Statistiche compressione ───────────────────────────────── */
typedef struct CompressionStats {
    uint64_t total_compress_ops;
    uint64_t total_decompress_ops;
    uint64_t bytes_before;       /* Bytes totali prima compressione */
    uint64_t bytes_after;        /* Bytes totali dopo compressione */
    double avg_ratio;            /* Ratio medio (bytes_after/bytes_before) */
    double avg_compress_us;      /* Latenza media compressione µs */
    double avg_decompress_us;    /* Latenza media decompressione µs */
    uint64_t skipped_too_small;  /* Skippate: dati troppo piccoli */
    uint64_t skipped_no_benefit; /* Skippate: compressione non aiuta */
} CompressionStats;

/* ── API pubblica ───────────────────────────────────────────── */

/**
 * compression_init - Inizializza il subsistema di compressione.
 * Prealloca i context Zstd/LZ4 per performance ottimale.
 */
int compression_init(void);

/**
 * compression_shutdown - Libera i context.
 */
void compression_shutdown(void);

/**
 * auto_select_compression - Seleziona il miglior algoritmo.
 *
 * @data:      Dati da analizzare
 * @size:      Dimensione dati
 * @data_type: Hint sul tipo di dato
 *
 * Returns: CompressionType raccomandato.
 */
CompressionType auto_select_compression(const uint8_t *data,
                                        size_t size,
                                        DataType data_type);

/**
 * compress_data - Comprime i dati con l'algoritmo scelto.
 *
 * @src:       Dati sorgente
 * @src_size:  Dimensione sorgente
 * @dst:       Buffer destinazione (deve essere large abbastanza)
 * @dst_cap:   Capacità buffer destinazione
 * @comp_type: Algoritmo da usare (COMPRESS_NONE per auto)
 * @data_type: Tipo di dato (hint)
 *
 * Returns: dimensione compressa, o -1 su errore.
 *          Restituisce 0 se la compressione non è conveniente
 *          (il chiamante deve usare i dati originali).
 */
ssize_t compress_data(const uint8_t *src,
                      size_t src_size,
                      uint8_t *dst,
                      size_t dst_cap,
                      CompressionType comp_type,
                      DataType data_type);

/**
 * decompress_data - Decomprime i dati.
 *
 * @src:       Dati compressi (con header CompressedHeader)
 * @src_size:  Dimensione dati compressi
 * @dst:       Buffer destinazione
 * @dst_cap:   Capacità buffer (deve essere >= original_size nell'header)
 *
 * Returns: dimensione decompressa, o -1 su errore.
 */
ssize_t decompress_data(const uint8_t *src,
                        size_t src_size,
                        uint8_t *dst,
                        size_t dst_cap);

/**
 * compress_estimate_bound - Stima dimensione massima output compresso.
 * Usare per allocare il buffer dst prima di compress_data().
 */
size_t compress_estimate_bound(size_t src_size, CompressionType comp_type);

/**
 * compression_get_stats - Statistiche del subsistema.
 */
CompressionStats compression_get_stats(void);

/**
 * compression_print_stats - Stampa stats human-readable.
 */
void compression_print_stats(void);

/* ── Delta encoding per Time Series ────────────────────────── */

/**
 * delta_encode - Codifica una serie temporale con delta+zigzag.
 * Efficiente per serie con piccole variazioni tra valori consecutivi.
 *
 * @values:   Array di double (valori time series)
 * @count:    Numero di valori
 * @out:      Buffer output
 * @out_cap:  Capacità buffer output
 *
 * Returns: bytes scritti, -1 su errore.
 */
ssize_t delta_encode(const double *values,
                     size_t count,
                     uint8_t *out,
                     size_t out_cap);

/**
 * delta_decode - Decodifica una serie delta-encoded.
 */
ssize_t delta_decode(const uint8_t *data,
                     size_t data_size,
                     double *out_values,
                     size_t out_cap_count);

#endif /* NEXCACHE_COMPRESSION_H */
