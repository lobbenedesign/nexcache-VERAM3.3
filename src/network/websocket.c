/* NexCache WebSocket RFC 6455 — Implementazione
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include "websocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>

/* ── SHA1 minimale per WebSocket handshake ──────────────────── */
/* Implementazione SHA1 RFC 3174 in-house per evitare dipendenze */

typedef struct {
    uint32_t h[5];
    uint8_t buf[64];
    uint32_t len, total;
} SHA1Ctx;

static void sha1_init(SHA1Ctx *c) {
    c->h[0] = 0x67452301;
    c->h[1] = 0xEFCDAB89;
    c->h[2] = 0x98BADCFE;
    c->h[3] = 0x10325476;
    c->h[4] = 0xC3D2E1F0;
    c->len = 0;
    c->total = 0;
}

#define SHA1_ROL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static void sha1_process(SHA1Ctx *c, const uint8_t *blk) {
    uint32_t w[80], a, b, d, e, f, k, t;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
               ((uint32_t)blk[i * 4 + 2] << 8) | (uint32_t)blk[i * 4 + 3];
    for (int i = 16; i < 80; i++)
        w[i] = SHA1_ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t cc = c->h[2];
    a = c->h[0];
    b = c->h[1];
    d = c->h[3];
    e = c->h[4];
    (void)cc;
    for (int i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & cc) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ cc ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & cc) | (b & d) | (cc & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ cc ^ d;
            k = 0xCA62C1D6;
        }
        t = SHA1_ROL(a, 5) + f + e + k + w[i];
        e = d;
        d = cc;
        cc = SHA1_ROL(b, 30);
        b = a;
        a = t;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
}

static void sha1_update(SHA1Ctx *c, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        c->buf[c->len++] = data[i];
        c->total++;
        if (c->len == 64) {
            sha1_process(c, c->buf);
            c->len = 0;
        }
    }
}

static void sha1_final(SHA1Ctx *c, uint8_t out[20]) {
    c->buf[c->len++] = 0x80;
    if (c->len > 56) {
        while (c->len < 64) c->buf[c->len++] = 0;
        sha1_process(c, c->buf);
        c->len = 0;
    }
    while (c->len < 56) c->buf[c->len++] = 0;
    uint64_t bits = (uint64_t)c->total * 8;
    for (int i = 7; i >= 0; i--) {
        c->buf[56 + i] = (uint8_t)(bits & 0xFF);
        bits >>= 8;
    }
    sha1_process(c, c->buf);
    for (int i = 0; i < 5; i++) {
        out[i * 4] = (c->h[i] >> 24) & 0xFF;
        out[i * 4 + 1] = (c->h[i] >> 16) & 0xFF;
        out[i * 4 + 2] = (c->h[i] >> 8) & 0xFF;
        out[i * 4 + 3] = c->h[i] & 0xFF;
    }
}

/* ── Base64 encoding ────────────────────────────────────────── */
static const char b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    static const char B[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, j = 0;
    while (i < in_len) {
        uint32_t octet_a = in[i++];
        uint32_t octet_b = (i < in_len) ? in[i++] : 0;
        uint32_t octet_c = (i < in_len) ? in[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        if (j + 5 > out_cap) return -1;
        out[j++] = B[(triple >> 18) & 0x3F];
        out[j++] = B[(triple >> 12) & 0x3F];
        out[j++] = B[(triple >> 6) & 0x3F];
        out[j++] = B[triple & 0x3F];
    }
    /* Applica padding corretto SOVRASCRIVENDO gli ultimi caratteri */
    if (in_len % 3 == 1) {
        /* 1 byte rimasto: gli ultimi 2 chars diventano "=="  */
        out[j - 2] = '=';
        out[j - 1] = '=';
    } else if (in_len % 3 == 2) {
        /* 2 bytes rimasti: l'ultimo char diventa "=" */
        out[j - 1] = '=';
    }
    out[j] = '\0';
    return (int)j;
}

/* ── ws_compute_accept_key ──────────────────────────────────── */
void ws_compute_accept_key(const char *client_key, char *out_key) {
    if (!client_key || !out_key) return;

    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s", client_key, WS_GUID);

    SHA1Ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (uint8_t *)combined, strlen(combined));
    uint8_t digest[20];
    sha1_final(&ctx, digest);

    base64_encode(digest, 20, out_key, 64);
}

/* ── ws_detect_upgrade ──────────────────────────────────────── */
int ws_detect_upgrade(const uint8_t *data, size_t len) {
    if (!data || len < 4) return 0;
    /* Cerca "Upgrade:" nel buffer HTTP */
    if (memmem(data, len, "Upgrade: websocket", 18) ||
        memmem(data, len, "upgrade: websocket", 18) ||
        memmem(data, len, "Upgrade:websocket", 17)) {
        return 1;
    }
    return 0;
}

/* ── ws_handshake ───────────────────────────────────────────── */
int ws_handshake(WsConn *conn, const char *request, size_t req_len) {
    if (!conn || !request) return -1;

    /* Estrai Sec-WebSocket-Key */
    const char *key_str = "Sec-WebSocket-Key: ";
    char *key_start = memmem(request, req_len, key_str, strlen(key_str));
    if (!key_start) key_str = "sec-websocket-key: ";
    key_start = memmem(request, req_len, key_str, strlen(key_str));
    if (!key_start) return -1;

    key_start += strlen(key_str);
    /* PRIMA: il loop cercava '\r'/'\n' avanzando da key_start senza mai
     * controllare di restare dentro request[0..req_len). Una richiesta
     * HTTP di upgrade malformata/troncata (header "Sec-WebSocket-Key:"
     * senza CRLF terminale prima della fine del buffer) faceva leggere
     * fino a 63 byte oltre la fine del buffer allocato dal chiamante
     * (heap/stack over-read). Ora il limite superiore include anche la
     * fine reale della richiesta. */
    const char *req_end = request + req_len;
    char client_key[64] = {0};
    int key_len = 0;
    while (key_start + key_len < req_end &&
           key_start[key_len] != '\r' && key_start[key_len] != '\n' &&
           key_len < 63) {
        client_key[key_len] = key_start[key_len];
        key_len++;
    }
    client_key[key_len] = '\0';

    /* Calcola accept key */
    char accept_key[64];
    ws_compute_accept_key(client_key, accept_key);

    /* Scrivi risposta HTTP 101 */
    char response[512];
    int resp_len = snprintf(response, sizeof(response),
                            "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: %s\r\n"
                            "Sec-WebSocket-Version: " WS_VERSION "\r\n"
                            "\r\n",
                            accept_key);

    ssize_t sent = send(conn->fd, response, (size_t)resp_len, 0);
    if (sent != resp_len) return -1;

    conn->state = WS_STATE_OPEN;
    fprintf(stderr, "[NexCache WS] Handshake OK client_id=%llu\n",
            (unsigned long long)conn->client_id);
    return 0;
}

/* ── ws_conn_create ─────────────────────────────────────────── */
WsConn *ws_conn_create(int fd, uint64_t client_id) {
    WsConn *conn = (WsConn *)calloc(1, sizeof(WsConn));
    if (!conn) return NULL;
    conn->fd = fd;
    conn->state = WS_STATE_CONNECTING;
    conn->client_id = client_id;

    conn->read_cap = 65536;
    conn->read_buf = (uint8_t *)malloc(conn->read_cap);
    conn->write_cap = 65536;
    conn->write_buf = (uint8_t *)malloc(conn->write_cap);

    if (!conn->read_buf || !conn->write_buf) {
        free(conn->read_buf);
        free(conn->write_buf);
        free(conn);
        return NULL;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    conn->connected_at_us = (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
    return conn;
}

/* ── ws_mask_payload ────────────────────────────────────────── */
void ws_mask_payload(uint8_t *data, size_t len, const uint8_t mask[4]) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= mask[i % 4];
    }
}

/* ── ws_send_frame ───────────────────────────────────────────── */
static int ws_send_frame(WsConn *conn, uint8_t opcode, const uint8_t *data, size_t data_len) {
    if (!conn || conn->state != WS_STATE_OPEN) return -1;

    /* Frame header: max 10 bytes */
    uint8_t header[10];
    int hlen = 0;

    header[hlen++] = 0x80 | opcode; /* FIN=1 + opcode */

    /* Payload length (server→client: no masking) */
    if (data_len <= 125) {
        header[hlen++] = (uint8_t)data_len;
    } else if (data_len <= 65535) {
        header[hlen++] = 126;
        header[hlen++] = (uint8_t)(data_len >> 8);
        header[hlen++] = (uint8_t)(data_len & 0xFF);
    } else {
        header[hlen++] = 127;
        for (int i = 7; i >= 0; i--)
            header[hlen++] = (uint8_t)((data_len >> (i * 8)) & 0xFF);
    }

    /* Invia header */
    if (send(conn->fd, header, (size_t)hlen, 0) < 0) return -1;

    /* Invia payload */
    if (data && data_len > 0) {
        if (send(conn->fd, data, data_len, 0) < 0) return -1;
    }

    conn->frames_sent++;
    conn->bytes_sent += (uint64_t)(hlen + data_len);
    return 0;
}

/* ── API pubblica send ──────────────────────────────────────── */
int ws_send_text(WsConn *conn, const char *text, size_t text_len) {
    return ws_send_frame(conn, WS_OP_TEXT, (uint8_t *)text, text_len);
}

int ws_send_binary(WsConn *conn, const uint8_t *data, size_t data_len) {
    return ws_send_frame(conn, WS_OP_BINARY, data, data_len);
}

int ws_send_ping(WsConn *conn) {
    return ws_send_frame(conn, WS_OP_PING, NULL, 0);
}

int ws_send_close(WsConn *conn, uint16_t code, const char *reason) {
    uint8_t payload[128];
    payload[0] = (uint8_t)(code >> 8);
    payload[1] = (uint8_t)(code & 0xFF);
    size_t rlen = 0;
    if (reason) {
        rlen = strlen(reason);
        if (rlen > 120) rlen = 120;
        memcpy(payload + 2, reason, rlen);
    }
    conn->state = WS_STATE_CLOSING;
    return ws_send_frame(conn, WS_OP_CLOSE, payload, 2 + rlen);
}

/* ── ws_read_frame (parsing) ────────────────────────────────── */
int ws_read_frame(WsConn *conn, WsFrame *frame) {
    if (!conn || !frame) return -1;
    if (conn->state != WS_STATE_OPEN) return -1;

    /* PRIMA: read_cap era fisso a 65536 byte e non veniva mai fatto
     * crescere, mentre WS_MAX_PAYLOAD dichiara frame fino a 16MB. Appena
     * il buffer si riempiva (read_cap - read_len == 0), recv(fd, ..., 0,
     * ...) ritornava 0, interpretato subito sotto come "connessione
     * chiusa dal peer" — qualunque frame WS singolo oltre ~64KB (ben
     * dentro il limite dichiarato) veniva quindi disconnesso invece che
     * accettato. Ora il buffer cresce fino a WS_MAX_PAYLOAD prima di
     * leggere, cosa possibile perché il chiamante non tiene puntatori
     * a read_buf tra una ws_read_frame() e l'altra. */
    if (conn->read_cap - conn->read_len < 4096 && conn->read_cap < WS_MAX_PAYLOAD) {
        size_t new_cap = conn->read_cap * 2;
        if (new_cap > WS_MAX_PAYLOAD + 16) new_cap = WS_MAX_PAYLOAD + 16;
        uint8_t *nb = (uint8_t *)realloc(conn->read_buf, new_cap);
        if (nb) {
            conn->read_buf = nb;
            conn->read_cap = new_cap;
        }
    }

    /* Leggi dati disponibili nel buffer */
    ssize_t n = 0;
    if (conn->read_cap > conn->read_len) {
        n = recv(conn->fd, conn->read_buf + conn->read_len,
                 conn->read_cap - conn->read_len, MSG_DONTWAIT);
    }
    if (n > 0)
        conn->read_len += (size_t)n;
    else if (n == 0 && conn->read_cap > conn->read_len)
        return -1; /* Connection closed (solo se avevamo davvero provato a leggere) */
    else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        return -1;

    if (conn->read_len < 2) return 0; /* Serve altro */

    uint8_t *buf = conn->read_buf;
    size_t avail = conn->read_len;

    frame->fin = (buf[0] >> 7) & 0x1;
    frame->opcode = buf[0] & 0x0F;
    frame->masked = (buf[1] >> 7) & 0x1;

    uint64_t payload_len = buf[1] & 0x7F;
    size_t offset = 2;

    if (payload_len == 126) {
        if (avail < 4) return 0;
        payload_len = ((uint64_t)buf[2] << 8) | buf[3];
        offset = 4;
    } else if (payload_len == 127) {
        if (avail < 10) return 0;
        payload_len = 0;
        for (int i = 0; i < 8; i++)
            payload_len = (payload_len << 8) | buf[2 + i];
        offset = 10;
    }

    if (payload_len > WS_MAX_PAYLOAD) return -1;

    if (frame->masked) {
        if (avail < offset + 4) return 0;
        memcpy(frame->masking_key, buf + offset, 4);
        offset += 4;
    }

    if (avail < offset + payload_len) return 0; /* Serve altro */

    frame->payload_len = payload_len;

    /* Alloca o riusa buffer payload */
    if (frame->payload_cap < payload_len) {
        free(frame->payload);
        frame->payload = (uint8_t *)malloc(payload_len + 1);
        frame->payload_cap = payload_len;
    }
    memcpy(frame->payload, buf + offset, (size_t)payload_len);

    if (frame->masked) {
        ws_mask_payload(frame->payload, (size_t)payload_len, frame->masking_key);
    }
    if (payload_len > 0) frame->payload[payload_len] = '\0';

    /* Consuma i bytes dal read buffer */
    size_t frame_size = offset + (size_t)payload_len;
    memmove(buf, buf + frame_size, conn->read_len - frame_size);
    conn->read_len -= frame_size;

    conn->frames_received++;
    conn->bytes_received += frame_size;

    return 1; /* Frame completo */
}

/* Scrive src in dst come stringa JSON escapata (senza virgolette esterne).
 * PRIMA: error/req_id (e result quando trattato come stringa grezza)
 * venivano interpolati verbatim in una struttura JSON via snprintf. Un
 * solo `"` in un messaggio di errore o in un valore di cache echeggiato
 * come result rompeva la struttura JSON e poteva iniettare campi
 * arbitrari nella risposta — reachable con dati cache controllati da un
 * attaccante (ws_process_command può restituire come result un valore
 * qualunque letto dalla cache). */
static size_t ws_json_escape(const char *src, char *dst, size_t dst_cap) {
    size_t o = 0;
    if (!src) return 0;
    for (const unsigned char *p = (const unsigned char *)src; *p && o + 6 < dst_cap; p++) {
        switch (*p) {
            case '"':  dst[o++] = '\\'; dst[o++] = '"';  break;
            case '\\': dst[o++] = '\\'; dst[o++] = '\\'; break;
            case '\n': dst[o++] = '\\'; dst[o++] = 'n';  break;
            case '\r': dst[o++] = '\\'; dst[o++] = 'r';  break;
            case '\t': dst[o++] = '\\'; dst[o++] = 't';  break;
            default:
                if (*p < 0x20) {
                    o += (size_t)snprintf(dst + o, dst_cap - o, "\\u%04x", *p);
                } else {
                    dst[o++] = (char)*p;
                }
        }
    }
    dst[o < dst_cap ? o : dst_cap - 1] = '\0';
    return o;
}

/* ── ws_send_response ───────────────────────────────────────── */
int ws_send_response(WsConn *conn, const char *req_id, const char *result, const char *error) {
    if (!conn) return -1;
    char buf[8192];
    char esc_a[2048], esc_b[2048];
    int len;
    if (error) {
        ws_json_escape(error, esc_a, sizeof(esc_a));
        ws_json_escape(req_id, esc_b, sizeof(esc_b));
        len = snprintf(buf, sizeof(buf),
                       "{\"ok\":false,\"error\":\"%s\",\"id\":\"%s\"}",
                       esc_a, esc_b);
    } else {
        int result_is_json_literal = result && result[0] == '"';
        if (result && !result_is_json_literal) {
            /* result grezzo (non già una stringa JSON quotata dal
             * chiamante): va escapato prima di essere quotato qui. */
            ws_json_escape(result, esc_a, sizeof(esc_a));
        }
        ws_json_escape(req_id, esc_b, sizeof(esc_b));
        len = snprintf(buf, sizeof(buf),
                       "{\"ok\":true,\"result\":%s%s%s,\"id\":\"%s\"}",
                       result_is_json_literal ? "" : "\"",
                       result ? (result_is_json_literal ? result : esc_a) : "null",
                       result_is_json_literal ? "" : "\"",
                       esc_b);
    }
    return ws_send_text(conn, buf, (size_t)len);
}

/* ── ws_conn_destroy ────────────────────────────────────────── */
void ws_conn_destroy(WsConn *conn) {
    if (!conn) return;
    if (conn->state == WS_STATE_OPEN) {
        ws_send_close(conn, 1000, "Server shutdown");
    }
    close(conn->fd);
    free(conn->read_buf);
    free(conn->write_buf);
    free(conn->current_frame.payload);
    for (int i = 0; i < conn->sub_count; i++)
        free(conn->subscribed_channels[i]);
    free(conn->subscribed_channels);
    free(conn);
}
