/* NexCache Tests — Moduli Core v2.0
 * Test unitari per TaggedPtr, ProtocolDetect, Prefetch,
 * WebSocket handshake, Cosine Similarity, RESP compat.
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* Include dei moduli da testare */
#include "../src/memory/prefetch.h"
#include "../src/memory/tagged_ptr.h"
#include "../src/network/protocol_detect.h"

/* ── Colori terminal ────────────────────────────────────────── */
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"
#define BOLD "\033[1m"

static int tests_passed = 0;
static int tests_failed = 0;
static int tests_total = 0;

static void test_pass(const char *name) {
  tests_passed++;
  tests_total++;
  printf(GREEN "  ✓ PASS" RESET " %s\n", name);
}

static void test_fail(const char *name, const char *reason) {
  tests_failed++;
  tests_total++;
  printf(RED "  ✗ FAIL" RESET " %s — %s\n", name, reason);
}

static uint64_t us_now(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* ─────────────────────────────────────────────────────────────
 * SUITE 1: Tagged Pointers
 * Nomi corretti dall'header: TaggedPtr, tptr_*, NEXTYPE_*, TPTR_FLAG_*
 * ───────────────────────────────────────────────────────────── */
static void test_tagged_ptr(void) {
  printf(BOLD "\n[Suite 1] Tagged Pointers\n" RESET);

  int data = 42;

  /* Test 1: crea un tagged pointer e recupera l'indirizzo */
  TaggedPtr tp = tptr_create(&data, NEXTYPE_STRING, 0, 0, 0);
  if (tptr_ptr(tp) == &data)
    test_pass("create + tptr_ptr");
  else
    test_fail("create + tptr_ptr", "pointer mismatch");

  /* Test 2: tipo STRING */
  if (tptr_type(tp) == NEXTYPE_STRING)
    test_pass("tptr_type → STRING");
  else
    test_fail("tptr_type → STRING", "wrong type");

  /* Test 3: tipo LIST */
  TaggedPtr tp2 = tptr_create(&data, NEXTYPE_LIST, 0, 0, 0);
  if (tptr_type(tp2) == NEXTYPE_LIST)
    test_pass("tptr_type → LIST");
  else
    test_fail("tptr_type → LIST", "wrong type");

  /* Test 4: tipo VECTOR */
  TaggedPtr tp3 = tptr_create(&data, NEXTYPE_VECTOR, 0, 0, 0);
  if (tptr_type(tp3) == NEXTYPE_VECTOR)
    test_pass("tptr_type → VECTOR");
  else
    test_fail("tptr_type → VECTOR", "wrong type");

  /* Test 5: NULL pointer */
  TaggedPtr null_tp = TPTR_NULL;
  if (tptr_is_null(null_tp))
    test_pass("TPTR_NULL → tptr_is_null");
  else
    test_fail("TPTR_NULL", "null not detected");

  /* Test 6: flag COMPRESSED */
  TaggedPtr tp4 = tptr_create(&data, NEXTYPE_HASH, 0, TPTR_FLAG_COMPRESSED, 0);
  if (tptr_flags(tp4) & TPTR_FLAG_COMPRESSED)
    test_pass("flag TPTR_FLAG_COMPRESSED");
  else
    test_fail("flag TPTR_FLAG_COMPRESSED", "not set");

  /* Test 7: version bump.
   * tptr_version/tptr_set_version degradano deliberatamente a no-op
   * quando g_nexarch.metadata_bits < 16 (non ci sono abbastanza bit
   * liberi nel puntatore per un campo versione separato — su questo
   * arch, es. ARM64 via TBI, sono disponibili solo 8 bit totali per
   * type+subtype+flags). Il test deve verificare il comportamento
   * corretto per l'architettura corrente, non assumere 16+ bit ovunque. */
  TaggedPtr tp5 = tptr_create(&data, NEXTYPE_STRING, 0, 0, 0);
  TaggedPtr tp5v = tptr_bump_version(tp5);
  if (g_nexarch.metadata_bits < 16) {
    if (tptr_version(tp5v) == 0)
      test_pass("tptr_bump_version: no-op su metadata_bits<16 (atteso)");
    else
      test_fail("tptr_bump_version", "doveva restare 0 su metadata_bits<16");
  } else if (tptr_version(tp5v) == 1) {
    test_pass("tptr_bump_version v0→v1");
  } else {
    char msg[64];
    snprintf(msg, sizeof(msg), "version=%d", tptr_version(tp5v));
    test_fail("tptr_bump_version", msg);
  }

  /* Test 8: tptr_type_name */
  if (strcmp(tptr_type_name(tp), "string") == 0 &&
      strcmp(tptr_type_name(tp2), "list") == 0 &&
      strcmp(tptr_type_name(tp3), "vector") == 0)
    test_pass("tptr_type_name strings");
  else
    test_fail("tptr_type_name", "wrong names");

  /* Test 9: TPTR_MARK_DIRTY macro */
  TaggedPtr tp6 = TPTR_SIMPLE(&data, NEXTYPE_JSON);
  tp6 = TPTR_MARK_DIRTY(tp6);
  if (tptr_is_dirty(tp6))
    test_pass("TPTR_MARK_DIRTY → tptr_is_dirty");
  else
    test_fail("TPTR_MARK_DIRTY", "flag not set");

  /* Test 10: TPTR_MARK_COLD macro.
   * FIX 2026-08-07: il layout flags ora si adatta a g_nexarch.metadata_bits
   * (vedi tagged_ptr.h) — con >=10 bit disponibili (il caso comune su
   * x86-64 senza LA57, 16 bit) TPTR_FLAG_COLD è pienamente rappresentabile.
   * Su architetture con budget più stretto (ARM64 TBI=8 bit, come questa
   * macchina) il flag degrada a no-op silenzioso, quindi il test verifica
   * il comportamento corretto per l'architettura corrente invece di
   * assumere sempre il caso "wide". */
  TaggedPtr tp7 = TPTR_SIMPLE(&data, NEXTYPE_TIMESERIES);
  tp7 = TPTR_MARK_COLD(tp7);
  if (NEXPTR_FLAGS_WIDE) {
    if (tptr_is_cold(tp7))
      test_pass("TPTR_MARK_COLD → tptr_is_cold (wide flags)");
    else
      test_fail("TPTR_MARK_COLD", "flag not set nonostante metadata_bits>=10");
  } else {
    if (!tptr_is_cold(tp7))
      test_pass("TPTR_MARK_COLD: no-op su metadata_bits<10 (atteso)");
    else
      test_fail("TPTR_MARK_COLD", "doveva restare non impostato su metadata_bits<10");
  }
}

/* ─────────────────────────────────────────────────────────────
 * SUITE 2: Protocol Auto-Detection
 * ───────────────────────────────────────────────────────────── */
static void test_protocol_detect(void) {
  printf(BOLD "\n[Suite 2] Protocol Auto-Detection\n" RESET);

  ProtoDetectResult result;

  /* Test 1: RESP2 — Array prefix * */
  const uint8_t resp2[] = "*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
  int r = protocol_detect(resp2, sizeof(resp2) - 1, &result);
  if (r == 0 && result.protocol == NEX_PROTO_RESP2)
    test_pass("RESP2 array detection");
  else
    test_fail("RESP2 array", "wrong protocol");

  /* Test 2: RESP2 inline */
  const uint8_t inline_cmd[] = "PING\r\n";
  r = protocol_detect(inline_cmd, sizeof(inline_cmd) - 1, &result);
  if (r == 0 && result.protocol == NEX_PROTO_RESP2)
    test_pass("RESP2 inline detection");
  else
    test_fail("RESP2 inline", "wrong protocol");

  /* Test 3: gRPC */
  const uint8_t grpc[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  r = protocol_detect(grpc, sizeof(grpc) - 1, &result);
  if (r == 0 && result.protocol == NEX_PROTO_GRPC)
    test_pass("gRPC detection");
  else
    test_fail("gRPC", "wrong protocol");

  /* Test 4: WebSocket upgrade */
  const uint8_t ws[] = "GET /nexcache HTTP/1.1\r\n"
                       "Host: localhost\r\n"
                       "Upgrade: websocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                       "Sec-WebSocket-Version: 13\r\n\r\n";
  r = protocol_detect(ws, sizeof(ws) - 1, &result);
  if (r == 0 && result.protocol == NEX_PROTO_WEBSOCKET)
    test_pass("WebSocket upgrade detection");
  else
    test_fail("WebSocket upgrade", "wrong protocol");

  /* Test 5: HTTP REST */
  const uint8_t http[] = "GET /api/v1/get?key=foo HTTP/1.1\r\n"
                         "Host: localhost:8080\r\n\r\n";
  r = protocol_detect(http, sizeof(http) - 1, &result);
  if (r == 0 && result.protocol == NEX_PROTO_HTTP_REST)
    test_pass("HTTP REST detection");
  else
    test_fail("HTTP REST", "wrong protocol");

  /* Test 6: TLS */
  const uint8_t tls[] = {0x16, 0x03, 0x03, 0x00, 0x00};
  r = protocol_detect(tls, sizeof(tls), &result);
  if (result.is_tls)
    test_pass("TLS detection (first byte 0x16)");
  else
    test_fail("TLS detection", "not detected as TLS");

  /* Test 7: GraphQL over WebSocket */
  const uint8_t gql[] = "GET /graphql HTTP/1.1\r\n"
                        "Host: localhost\r\n"
                        "Upgrade: websocket\r\n"
                        "Sec-WebSocket-Protocol: graphql-transport-ws\r\n"
                        "Connection: Upgrade\r\n\r\n";
  r = protocol_detect(gql, sizeof(gql) - 1, &result);
  if (r == 0 && result.protocol == NEX_PROTO_GRAPHQL)
    test_pass("GraphQL over WebSocket detection");
  else
    test_fail("GraphQL over WebSocket", "wrong protocol");

  /* Test 8: protocol_name */
  if (strcmp(protocol_name(NEX_PROTO_RESP2), "RESP2") == 0 &&
      strcmp(protocol_name(NEX_PROTO_GRPC), "gRPC") == 0 &&
      strcmp(protocol_name(NEX_PROTO_WEBSOCKET), "WebSocket") == 0)
    test_pass("protocol_name correctness");
  else
    test_fail("protocol_name", "wrong names");
}

/* ─────────────────────────────────────────────────────────────
 * SUITE 3: Memory Prefetch Hints
 * ───────────────────────────────────────────────────────────── */
static void test_prefetch(void) {
  printf(BOLD "\n[Suite 3] Memory Prefetch Hints\n" RESET);

  int arr[64];
  for (int i = 0; i < 64; i++)
    arr[i] = i;

  NEX_PREFETCH(&arr[0]);
  NEX_PREFETCH_L2(&arr[16]);
  NEX_PREFETCH_WRITE(&arr[32]);
  test_pass("prefetch macros compile and execute");

  nex_prefetch_read(NULL, PREFETCH_L1);
  test_pass("prefetch NULL no crash");

  void *ptrs[100];
  for (int i = 0; i < 100; i++)
    ptrs[i] = &arr[i % 64];
  for (int i = 0; i < 90; i++)
    nex_prefetch_array((const void **)ptrs, (size_t)i, 100);
  test_pass("prefetch_array stride no crash");

  NEX_MEMORY_FENCE();
  test_pass("memory fence executes");
}

/* ─────────────────────────────────────────────────────────────
 * SUITE 4: WebSocket RFC 6455 Accept Key
 * ───────────────────────────────────────────────────────────── */
extern void ws_compute_accept_key(const char *client_key, char *out_key);

static void test_websocket_handshake(void) {
  printf(BOLD "\n[Suite 4] WebSocket Handshake (RFC 6455)\n" RESET);

  char accept[64] = {0};
  ws_compute_accept_key("dGhlIHNhbXBsZSBub25jZQ==", accept);

  if (strcmp(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0)
    test_pass("RFC 6455 test vector SHA1+base64");
  else {
    char msg[128];
    snprintf(msg, sizeof(msg), "expected '...xOo=' got '%s'", accept);
    test_fail("RFC 6455 test vector", msg);
  }

  char accept2[64] = {0};
  ws_compute_accept_key("differentkey==", accept2);
  if (strcmp(accept, accept2) != 0)
    test_pass("different keys → different accepts");
  else
    test_fail("different keys", "collision detected");
}

/* ─────────────────────────────────────────────────────────────
 * SUITE 5: Cosine Similarity
 * ───────────────────────────────────────────────────────────── */
static float test_cosine(const float *a, const float *b, int dim) {
  double dot = 0, na = 0, nb = 0;
  for (int i = 0; i < dim; i++) {
    dot += (double)a[i] * b[i];
    na += (double)a[i] * a[i];
    nb += (double)b[i] * b[i];
  }
  double denom = sqrt(na) * sqrt(nb);
  if (denom < 1e-12)
    return 0.0f;
  return (float)(dot / denom);
}

static void test_cosine_similarity(void) {
  printf(BOLD "\n[Suite 5] Cosine Similarity\n" RESET);

  float a1[] = {1.0f, 2.0f, 3.0f, 4.0f};
  float sim = test_cosine(a1, a1, 4);
  if (fabsf(sim - 1.0f) < 1e-5f)
    test_pass("identical vectors → 1.0");
  else {
    char msg[64];
    snprintf(msg, sizeof(msg), "sim=%.6f", sim);
    test_fail("identical vectors", msg);
  }

  float a2[] = {1.0f, 0.0f, 0.0f};
  float b2[] = {0.0f, 1.0f, 0.0f};
  sim = test_cosine(a2, b2, 3);
  if (fabsf(sim) < 1e-5f)
    test_pass("orthogonal → 0.0");
  else {
    char msg[64];
    snprintf(msg, sizeof(msg), "sim=%.6f", sim);
    test_fail("orthogonal", msg);
  }

  float a3[] = {1.0f, 0.0f, 0.0f};
  float b3[] = {-1.0f, 0.0f, 0.0f};
  sim = test_cosine(a3, b3, 3);
  if (fabsf(sim + 1.0f) < 1e-5f)
    test_pass("opposite → -1.0");
  else {
    char msg[64];
    snprintf(msg, sizeof(msg), "sim=%.6f", sim);
    test_fail("opposite", msg);
  }

  int dim = 1536;
  float *hi_a = (float *)calloc((size_t)dim, sizeof(float));
  float *hi_b = (float *)calloc((size_t)dim, sizeof(float));
  for (int i = 0; i < dim; i++) {
    hi_a[i] = (float)i / dim;
    hi_b[i] = (float)i / dim + 0.0001f;
  }
  uint64_t t0 = us_now();
  sim = test_cosine(hi_a, hi_b, dim);
  uint64_t elapsed = us_now() - t0;
  free(hi_a);
  free(hi_b);

  if (sim > 0.99f)
    test_pass("dim=1536 near-identical > 0.99");
  else {
    char msg[64];
    snprintf(msg, sizeof(msg), "sim=%.4f", sim);
    test_fail("dim=1536", msg);
  }
  printf("    cosine(1536 dim): %llu µs\n", (unsigned long long)elapsed);

  if (elapsed < 100)
    test_pass("cosine(1536) < 100µs");
  else {
    char msg[64];
    snprintf(msg, sizeof(msg), "%llu µs", (unsigned long long)elapsed);
    test_fail("cosine(1536) performance", msg);
  }
}

/* ─────────────────────────────────────────────────────────────
 * SUITE 6: RESP Protocol Compatibility
 * ───────────────────────────────────────────────────────────── */
static void test_resp_compat(void) {
  printf(BOLD "\n[Suite 6] RESP Protocol Compatibility\n" RESET);

  ProtoDetectResult result;
  const char *resp_samples[] = {"*1\r\n$4\r\nPING\r\n",     "+OK\r\n",
                                "-ERR unknown command\r\n", ":42\r\n",
                                "$5\r\nhello\r\n",          NULL};

  int all_ok = 1;
  for (int i = 0; resp_samples[i]; i++) {
    int r = protocol_detect((const uint8_t *)resp_samples[i],
                            strlen(resp_samples[i]), &result);
    if (r == 0 && result.protocol == NEX_PROTO_RESP2)
      continue;
    all_ok = 0;
    printf("    Failed on: %s\n", resp_samples[i]);
  }
  if (all_ok)
    test_pass("all RESP2 types detected");
  else
    test_fail("RESP2 types", "some failed");
}

/* ─────────────────────────────────────────────────────────────
 * MAIN
 * ───────────────────────────────────────────────────────────── */
int main(void) {
  printf(BOLD "\n╔══════════════════════════════════════════════╗\n"
              "║   NexCache — Test Suite v2.0                ║\n"
              "╚══════════════════════════════════════════════╝\n" RESET);

  uint64_t t0 = us_now();

  /* memory/tagged_ptr.h documenta esplicitamente: "deve essere chiamata
   * PRIMA di qualsiasi [uso]" — senza questa chiamata g_nexarch resta
   * a zero (addr_mask=0, metadata_shift=0), e tptr_ptr() azzera sempre
   * il puntatore. BUG SCOPERTO oggi rimettendo in funzione questa suite:
   * nexarch_probe() non viene chiamata da NESSUNA parte in tutto il
   * codebase (verificato con grep globale), nemmeno da questo stesso
   * test file nella sua versione precedente — il modulo tagged_ptr.h
   * "v6" è incluso da core/engine.h ma non è mai usato da nessun
   * chiamante reale (nexdash.h ha un proprio TaggedPtr separato e
   * incompatibile), quindi il bug non ha mai avuto un impatto in
   * produzione finora, ma se questo modulo viene mai attivato per
   * davvero senza questa chiamata di init, ogni tagged pointer creato
   * sarebbe silenziosamente corrotto. */
  if (nexarch_probe() != 0) {
    fprintf(stderr, "WARNING: nexarch_probe() reports unsupported architecture\n");
  }

  test_tagged_ptr();
  test_protocol_detect();
  test_prefetch();
  test_websocket_handshake();
  test_cosine_similarity();
  test_resp_compat();

  uint64_t elapsed = us_now() - t0;

  printf(BOLD "\n══════════════════════════════════════════════\n" RESET);
  printf("  Results:  %d/%d tests passed", tests_passed, tests_total);
  if (tests_failed > 0)
    printf(RED "  (%d FAILED)" RESET, tests_failed);
  printf("\n  Runtime:  %llu ms\n", (unsigned long long)(elapsed / 1000));
  if (tests_failed == 0)
    printf(GREEN "  ALL TESTS PASSED ✓\n" RESET);
  else
    printf(RED "  SOME TESTS FAILED ✗\n" RESET);
  printf("══════════════════════════════════════════════\n\n");

  return tests_failed > 0 ? 1 : 0;
}
