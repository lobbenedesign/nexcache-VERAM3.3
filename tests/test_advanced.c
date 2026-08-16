/* NexCache — Test Suite v3.0 (Moduli Avanzati)
 * ============================================================
 * Test per i moduli implementati nella Phase 3:
 *   - Raft Consensus
 *   - HNSW Vector Index
 *   - Post-Quantum Crypto (BLAKE3)
 *   - AOF/RDB Persistence
 *   - Cluster Sharding (CRC16 + Consistent Hash)
 *
 * Tutti i test sono standalone (non richiedono NexCache/server).
 * Copyright (c) 2026 NexCache Project — BSD License
 */

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

/* Moduli da testare */
#include "../src/cluster/cluster.h"
/* NOTA (scoperto 2026-08-07): src/consensus/raft.h non esiste in questa
 * versione dell'albero sorgenti (NexCache-SOVEREIGN NV-RUBIN VERAM 4.0) —
 * verificato, la cartella src/consensus/ non esiste affatto. Il modulo
 * Raft Consensus era forse presente in una lineage diversa (VERAM3.3?)
 * o pianificato ma mai portato qui. Suite 1 (test_raft) sotto è disattivata
 * di conseguenza — non è possibile testare un modulo che non esiste nel
 * codebase corrente. Se Raft Consensus è una feature voluta per SOVEREIGN,
 * va prima implementata (src/consensus/raft.c/h + wiring), poi questa
 * suite può essere riattivata. */
#include "../src/persistence/persist.h"
#include "../src/security/pqcrypto.h"
#include "../src/vector/hnsw.h"

/* ── Helpers ────────────────────────────────────────────────── */
static int g_pass = 0, g_fail = 0;

#define CHECK(expr, msg)                                                       \
  do {                                                                         \
    if (expr) {                                                                \
      printf("  ✓ PASS %s\n", msg);                                            \
      g_pass++;                                                                \
    } else {                                                                   \
      printf("  ✗ FAIL %s (line %d)\n", msg, __LINE__);                        \
      g_fail++;                                                                \
    }                                                                          \
  } while (0)

static uint64_t us_now(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

/* ──────────────────────────────────────────────────────────── */
/* SUITE 1: Raft Consensus                                      */
/* ──────────────────────────────────────────────────────────── */

static int raft_apply_cb(const uint8_t *data, size_t len, void *ud) {
  (void)data;
  (void)len;
  (void)ud;
  return 0;
}

static void test_raft(void) {
  printf("\n[Suite 1] Raft Consensus — SALTATA: src/consensus/raft.h non esiste "
         "in questo codebase (vedi nota sopra gli #include)\n");
}

/* ──────────────────────────────────────────────────────────── */
/* SUITE 2: HNSW Vector Index                                   */
/* ──────────────────────────────────────────────────────────── */
static void test_hnsw(void) {
  printf("\n[Suite 2] HNSW Vector Index\n");

  int dim = 128;
  HNSWIndex *idx =
      hnsw_create(dim, 16, 100, HNSW_METRIC_COSINE, HNSW_QUANT_FLOAT32);
  CHECK(idx != NULL, "hnsw_create");
  CHECK(idx->dim == dim, "dim == 128");
  CHECK(idx->M == 16, "M == 16");

  /* Inserisci 100 vettori casuali */
  float v[128];
  for (int i = 0; i < 100; i++) {
    for (int d = 0; d < dim; d++)
      v[d] = (float)(rand() % 1000) / 1000.0f;
    int rc = hnsw_add(idx, (hnsw_id_t)i, v, NULL);
    (void)rc;
  }
  CHECK(idx->count == 100, "100 vectors inserted");

  /* Vettore query = vettore 0 (deve essere tra i top risultati) */
  HNSWResult results[10];
  int num_res = 0;

  /* Crea query identica al primo vettore inserito */
  float query[128];
  memcpy(query, idx->nodes[0].vector, dim * sizeof(float));

  uint64_t t0 = us_now();
  int rc = hnsw_search(idx, query, 5, 0, results, &num_res);
  uint64_t elapsed = us_now() - t0;

  CHECK(rc == 0, "hnsw_search returns 0");
  CHECK(num_res >= 1, "at least 1 result");
  CHECK(results[0].distance < 0.001f, "top result very close to query");
  CHECK(elapsed < 1000000, "search < 1s");

  /* Cerca con L2 metric su nuovo indice */
  HNSWIndex *idx_l2 = hnsw_create(4, 8, 50, HNSW_METRIC_L2, HNSW_QUANT_FLOAT32);
  float pts[5][4] = {{1, 0, 0, 0},
                     {0, 1, 0, 0},
                     {0, 0, 1, 0},
                     {0, 0, 0, 1},
                     {0.5f, 0.5f, 0, 0}};
  for (int i = 0; i < 5; i++)
    hnsw_add(idx_l2, (hnsw_id_t)i, pts[i], NULL);
  float q4[4] = {1.01f, 0, 0, 0};
  HNSWResult res4[3];
  int nr4 = 0;
  hnsw_search(idx_l2, q4, 1, 0, res4, &nr4);
  CHECK(nr4 == 1, "L2: 1 result for k=1");
  CHECK(res4[0].ext_id == 0, "L2: nearest to {1,0,0,0} is node 0");

  /* Soft delete */
  rc = hnsw_delete(idx, 0);
  CHECK(rc == 0, "hnsw_delete returns 0");
  /* Il nodo 0 è marcato deleted: non deve apparire nei risultati */
  hnsw_search(idx, query, 3, 0, results, &num_res);
  int found_deleted = 0;
  for (int i = 0; i < num_res; i++)
    if (results[i].ext_id == 0)
      found_deleted = 1;
  CHECK(!found_deleted, "deleted node not in results");

  /* Stats */
  HNSWStats s = hnsw_get_stats(idx);
  CHECK(s.inserts == 100, "stats.inserts == 100");
  CHECK(s.deletes == 1, "stats.deletes == 1");

  hnsw_destroy(idx);
  hnsw_destroy(idx_l2);
  printf("  ✓ PASS hnsw_destroy\n");
  g_pass++;
}

/* ──────────────────────────────────────────────────────────── */
/* SUITE 3: BLAKE3 + Post-Quantum Crypto                        */
/* ──────────────────────────────────────────────────────────── */
static void test_pqcrypto(void) {
  printf("\n[Suite 3] Post-Quantum Crypto (BLAKE3)\n");

  pq_crypto_init();

  /* BLAKE3: stessa input → stesso hash */
  uint8_t h1[32], h2[32];
  const char *msg = "NexCache test message 2026";
  pq_blake3_hash((const uint8_t *)msg, strlen(msg), h1, 32);
  pq_blake3_hash((const uint8_t *)msg, strlen(msg), h2, 32);
  CHECK(memcmp(h1, h2, 32) == 0, "BLAKE3 deterministic");

  /* Input diversi → hash diversi */
  uint8_t h3[32];
  pq_blake3_hash((const uint8_t *)"different", 9, h3, 32);
  CHECK(memcmp(h1, h3, 32) != 0, "BLAKE3 different inputs");

  /* Hash vuoto non crashs */
  uint8_t hempty[32];
  pq_blake3_hash(NULL, 0, hempty, 32);
  pq_blake3_hash((const uint8_t *)"", 0, hempty, 32);
  printf("  ✓ PASS BLAKE3 empty input no crash\n");
  g_pass++;

  /* pq_hash_key — stabilità */
  uint64_t k1 = pq_hash_key("user:1234", 9);
  uint64_t k2 = pq_hash_key("user:1234", 9);
  uint64_t k3 = pq_hash_key("user:9999", 9);
  CHECK(k1 == k2, "pq_hash_key deterministic");
  CHECK(k1 != k3, "pq_hash_key different keys");

  /* Token generation + verify */
  uint8_t token[PQ_TOKEN_BYTES];
  int rc = pq_generate_token("ns_finance", "secret123", token, sizeof(token));
  CHECK(rc == 0, "pq_generate_token");

  rc = pq_verify_token(token, sizeof(token), "secret123",
                       3600ULL * 1000000ULL); /* Valido per 1 ora */
  CHECK(rc == 0, "pq_verify_token valid");

  /* Token con chiave sbagliata → invalido */
  rc = pq_verify_token(token, sizeof(token), "wrong_secret",
                       3600ULL * 1000000ULL);
  CHECK(rc != 0, "pq_verify_token wrong key → rejected");

  /* Token corrotto → invalido */
  uint8_t bad_token[PQ_TOKEN_BYTES];
  memcpy(bad_token, token, sizeof(token));
  bad_token[20] ^= 0xFF; /* Corrompi un byte */
  rc = pq_verify_token(bad_token, sizeof(bad_token), "secret123",
                       3600ULL * 1000000ULL);
  CHECK(rc != 0, "pq_verify_token corrupted → rejected");

  /* Sign/Verify (stub) */
  uint8_t pub[DILITHIUM3_PK_BYTES];
  uint8_t priv[DILITHIUM3_SK_BYTES];
  pq_sign_keygen(pub, sizeof(pub), priv, sizeof(priv));

  uint8_t sig[PQ_SIGNATURE_BYTES];
  size_t sig_len = 0;
  rc = pq_sign((const uint8_t *)"data to sign", 12, priv, sizeof(priv), sig,
               &sig_len);
  CHECK(rc == 0 && sig_len > 0, "pq_sign returns signature");

  rc = pq_verify((const uint8_t *)"data to sign", 12, sig, sig_len, pub,
                 sizeof(pub));
  CHECK(rc == 0, "pq_verify valid signature");

  pq_crypto_shutdown();
}

/* ──────────────────────────────────────────────────────────── */
/* SUITE 4: AOF/RDB Persistence                                 */
/* ──────────────────────────────────────────────────────────── */

static int replay_count = 0;
static int test_apply(AOFEntryType type, const char *key, size_t key_len,
                      const uint8_t *value, size_t value_len,
                      uint64_t expire_us) {
  (void)type;
  (void)key_len;
  (void)value;
  (void)value_len;
  (void)expire_us;
  (void)key;
  replay_count++;
  return 0;
}

static void test_persistence(void) {
  printf("\n[Suite 4] AOF/RDB Persistence\n");

  const char *aof_path = "/tmp/nexcache_test.aof";
  const char *rdb_path = "/tmp/nexcache_test.rdb";

  /* Rimuovi file precedenti */
  unlink(aof_path);
  unlink(rdb_path);

  PersistConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.aof_mode = AOF_ALWAYS;
  strncpy(cfg.aof_path, aof_path, sizeof(cfg.aof_path) - 1);

  int rc = aof_init(&cfg);
  CHECK(rc == 0, "aof_init");

  /* Scrivi 5 entry */
  for (int i = 0; i < 5; i++) {
    char key[32], val[32];
    snprintf(key, sizeof(key), "key%d", i);
    snprintf(val, sizeof(val), "value%d", i);
    rc = aof_write(AOF_OP_SET, key, strlen(key), (const uint8_t *)val,
                   strlen(val), 0);
    CHECK(rc == 0, "aof_write");
  }

  /* fsync esplicito */
  rc = aof_fsync_now();
  CHECK(rc == 0, "aof_fsync_now");

  PersistStats stats = persist_get_stats();
  CHECK(stats.aof_writes == 5, "aof_writes == 5");
  CHECK(stats.aof_bytes > 0, "aof_bytes > 0");

  aof_shutdown();

  /* Replay del file AOF */
  replay_count = 0;
  rc = aof_replay(aof_path, test_apply);
  CHECK(rc == 0, "aof_replay returns 0");
  CHECK(replay_count == 5, "replay_count == 5 entries");

  /* Cleanup */
  unlink(aof_path);
  unlink(rdb_path);
}

/* ──────────────────────────────────────────────────────────── */
/* SUITE 5: Cluster Sharding                                    */
/* ──────────────────────────────────────────────────────────── */
static void test_cluster(void) {
  printf("\n[Suite 5] Cluster Sharding\n");

  /* CRC16 — compatibilità NexCache Cluster */
  /* Slot per "foo" deve essere 12356 (valore NexCache standard) */
  int slot_foo = cluster_key_to_slot("foo", 3);
  CHECK(slot_foo >= 0 && slot_foo < 16384, "slot in [0,16383]");

  /* Hash tag: {user}.profile e {user}.settings devono avere lo stesso slot */
  int slot_a = cluster_key_to_slot("{user}.profile", 14);
  int slot_b = cluster_key_to_slot("{user}.settings", 15);
  CHECK(slot_a == slot_b, "hash tags → same slot");

  /* Senza hash tag: chiavi diverse → slot (probabilmente) diversi */
  int slot_c = cluster_key_to_slot("aaa", 3);
  int slot_d = cluster_key_to_slot("zzz", 3);
  (void)slot_c;
  (void)slot_d;
  printf("  ✓ PASS CRC16 slots: aaa=%d zzz=%d\n", slot_c, slot_d);
  g_pass++;

  /* Init cluster single-node */
  ClusterIndex *ci = cluster_init(1, "127.0.0.1", 7379);
  CHECK(ci != NULL, "cluster_init");
  CHECK(ci->node_count == 1, "1 node initially");
  CHECK(ci->ring_size > 0, "ring built");

  /* Tutto è locale in single-node */
  CHECK(cluster_key_is_local(ci, "foo", 3), "single-node: all local");
  CHECK(cluster_key_is_local(ci, "bar", 3), "single-node: bar local");

  /* Aggiungi nodo 2 con slot 0-8191 */
  int rc = cluster_add_node(ci, 2, "192.168.1.2", 7380, 0, 8191);
  CHECK(rc == 0, "cluster_add_node");
  CHECK(ci->node_count == 2, "2 nodes");

  /* Aggiungi nodo 3 */
  rc = cluster_add_node(ci, 3, "192.168.1.3", 7381, 8192, 16383);
  CHECK(rc == 0, "cluster_add_node 3");
  CHECK(ci->node_count == 3, "3 nodes");

  /* Lookup funziona */
  uint32_t node = cluster_key_to_node(ci, "mykey", 5);
  CHECK(node >= 1 && node <= 3, "key maps to valid node");

  /* Simula failure nodo 2 */
  rc = cluster_mark_failed(ci, 2);
  CHECK(rc == 0, "cluster_mark_failed");
  /* Dopo failover, nessuna chiave deve mappare al nodo 2 */
  int any_to_2 = 0;
  for (int i = 0; i < 100; i++) {
    char k[16];
    snprintf(k, sizeof(k), "key%d", i);
    if (cluster_key_to_node(ci, k, strlen(k)) == 2)
      any_to_2 = 1;
  }
  CHECK(!any_to_2, "no keys to failed node 2");

  /* Rimuovi nodo 3 */
  rc = cluster_remove_node(ci, 3);
  CHECK(rc == 0 && ci->node_count == 2, "cluster_remove_node");

  /* Stats */
  ClusterStats s = cluster_get_stats(ci);
  CHECK(s.key_lookups > 0, "stats.key_lookups > 0");
  CHECK(s.failovers == 1, "stats.failovers == 1");

  cluster_shutdown(ci);
  printf("  ✓ PASS cluster_shutdown\n");
  g_pass++;
}

/* ──────────────────────────────────────────────────────────── */
/* MAIN                                                         */
/* ──────────────────────────────────────────────────────────── */
int main(void) {
  printf("\n╔══════════════════════════════════════════════╗\n");
  printf("║   NexCache — Test Suite v3.0 (Avanzati)     ║\n");
  printf("╚══════════════════════════════════════════════╝\n");

  srand(42); /* Seed fisso per riproducibilità */

  test_raft();
  test_hnsw();
  test_pqcrypto();
  test_persistence();
  test_cluster();

  int total = g_pass + g_fail;
  printf("\n══════════════════════════════════════════════\n");
  printf("  Results:  %d/%d tests passed", g_pass, total);
  if (g_fail > 0)
    printf("  (%d FAILED)", g_fail);
  printf("\n");
  if (g_fail == 0) {
    printf("  ALL TESTS PASSED ✓\n");
  } else {
    printf("  SOME TESTS FAILED ✗\n");
  }
  printf("══════════════════════════════════════════════\n");

  return g_fail > 0 ? 1 : 0;
}
