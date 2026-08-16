/* NexCache Test Suite v4.0
 * Moduli: NexDashTable, VLL, CRDT, SubkeyTTL, NexSegcache,
 *         NexStorage Narrow-Waist, Anomaly Detection
 * Copyright (c) 2026 NexCache Project — BSD License
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/core/nexstorage.h"
#include "../src/core/subkey_ttl.h"
#include "../src/core/vll.h"
#include "../src/crdt/crdt.h"
#include "../src/hashtable/nexdash.h"
#include "../src/observability/anomaly.h"
#include "../src/segcache/segcache.h"

/* ── Harness ────────────────────────────────────────────────── */
static int tests_run = 0, tests_passed = 0, tests_failed = 0;

#define T_START(n)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [TEST] %-55s", n);                                               \
    fflush(stdout);                                                            \
  } while (0)
#define T_OK()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)
#define T_FAIL(r)                                                              \
  do {                                                                         \
    tests_failed++;                                                            \
    printf("FAIL — %s\n", r);                                                  \
  } while (0)

/* ── Helper callbacks ───────────────────────────────────────── */
static void snap_count_cb(const char *k, uint8_t kl, void *v, uint8_t type,
                          void *cx) {
  (*(int *)cx)++;
  (void)k;
  (void)kl;
  (void)v;
  (void)type;
}

/* ════════════════════════════════════════════════════════════════
 * MODULO 1 — NexDashTable
 * ══════════════════════════════════════════════════════════════ */
static void test_nexdash(void) {
  printf("\n── NexDashTable Tests ──────────────────────────────────\n");
  NexDashTable *t = nexdash_create(32, 64 * 1024 * 1024);

  T_START("NexDash: create");
  if (!t) {
    T_FAIL("NULL");
    return;
  }
  T_OK();

  T_START("NexDash: set + get string");
  {
    nexdash_set(t, "hello", 5, (void *)"world", 6, NTYPE_STRING, 0);
    NexEntryType tp;
    void *v = nexdash_get(t, "hello", 5, &tp);
    if (!v || strcmp((char *)v, "world") != 0 || tp != NTYPE_STRING) {
      T_FAIL("wrong value or type");
    } else
      T_OK();
  }

  T_START("NexDash: set/get 1000 keys");
  {
    char kb[32], vb[32];
    int ok = 1;
    for (int i = 0; i < 1000; i++) {
      snprintf(kb, sizeof(kb), "key:%05d", i);
      snprintf(vb, sizeof(vb), "val:%05d", i);
      nexdash_set(t, kb, (uint8_t)strlen(kb), strdup(vb), (uint32_t)(strlen(vb) + 1), NTYPE_STRING, 0);
    }
    for (int i = 0; i < 1000 && ok; i++) {
      snprintf(kb, sizeof(kb), "key:%05d", i);
      snprintf(vb, sizeof(vb), "val:%05d", i);
      NexEntryType tp;
      void *out = nexdash_get(t, kb, (uint8_t)strlen(kb), &tp);
      if (!out || strcmp((char *)out, vb) != 0)
        ok = 0;
    }
    if (!ok)
      T_FAIL("key mismatch");
    else
      T_OK();
  }

  T_START("NexDash: delete key");
  {
    nexdash_set(t, "todel", 5, (void *)"data", 5, NTYPE_STRING, 0);
    int d = nexdash_del(t, "todel", 5);
    NexEntryType tp;
    void *r = nexdash_get(t, "todel", 5, &tp);
    if (d != 1 || r != NULL)
      T_FAIL("del failed");
    else
      T_OK();
  }

  T_START("NexDash: exists");
  {
    nexdash_set(t, "ex1", 3, (void *)"v", 2, NTYPE_STRING, 0);
    int e1 = nexdash_exists(t, "ex1", 3);
    int e2 = nexdash_exists(t, "noex", 4);
    if (e1 != 1 || e2 != 0)
      T_FAIL("exists wrong");
    else
      T_OK();
  }

  T_START("NexDash: expire encoding round-trip");
  {
    uint64_t exp = (uint64_t)time(NULL) * 1000000ULL + 3600000000ULL;
    nexdash_set(t, "ttlkey", 6, (void *)"val", 4, NTYPE_STRING, exp);
    NexEntryType tp;
    void *out = nexdash_get(t, "ttlkey", 6, &tp);
    if (!out)
      T_FAIL("future TTL key not found");
    else
      T_OK();
  }

  T_START("NexDash: fork-less snapshot start/end");
  {
    int ok = (nexdash_snapshot_start(t) == 0);
    int cnt = 0;
    if (ok)
      nexdash_snapshot_iterate_full(t, snap_count_cb, &cnt);
    ok &= (nexdash_snapshot_end(t) == 0) && (cnt > 0);
    if (!ok)
      T_FAIL("snapshot failed");
    else
      T_OK();
  }

  T_START("NexDash: stats are populated");
  {
    NexDashStats s = nexdash_get_stats(t);
    if (s.sets == 0 || s.hits == 0)
      T_FAIL("stats empty");
    else
      T_OK();
  }

  nexdash_destroy(t);
}

/* ════════════════════════════════════════════════════════════════
 * MODULO 2 — VLL Transaction Manager
 * ══════════════════════════════════════════════════════════════ */
static void test_vll(void) {
  printf("\n── VLL Transaction Manager Tests ───────────────────────\n");
  VLLManager *mgr = vll_create(4096);

  T_START("VLL: create manager");
  if (!mgr) {
    T_FAIL("NULL");
    return;
  }
  T_OK();

  T_START("VLL: acquire/release write lock");
  {
    uint64_t h[1] = {0x123456789ABCDEF0ULL};
    VLLLockType lt[1] = {VLL_LOCK_WRITE};
    VLLRequest *req = vll_request_create(mgr, h, lt, 1);
    int ok = req && (vll_acquire(mgr, req) == VLL_OK);
    if (ok)
      vll_release(mgr, req);
    if (req)
      vll_request_destroy(req);
    if (!ok)
      T_FAIL("acquire failed");
    else
      T_OK();
  }

  T_START("VLL: no conflict on disjoint key sets");
  {
    uint64_t h1[1] = {0xAAAAAAAABBBBBBBBULL};
    uint64_t h2[1] = {0xCCCCCCCCDDDDDDDDULL};
    VLLLockType wt[1] = {VLL_LOCK_WRITE};
    VLLRequest *r1 = vll_request_create(mgr, h1, wt, 1);
    VLLRequest *r2 = vll_request_create(mgr, h2, wt, 1);
    int ok =
        (vll_acquire(mgr, r1) == VLL_OK) && (vll_acquire(mgr, r2) == VLL_OK);
    vll_release(mgr, r1);
    vll_release(mgr, r2);
    vll_request_destroy(r1);
    vll_request_destroy(r2);
    if (!ok)
      T_FAIL("conflict on disjoint");
    else
      T_OK();
  }

  T_START("VLL: stats committed > 0");
  {
    VLLStats s = vll_get_stats(mgr);
    if (s.txns_committed < 3)
      T_FAIL("committed < 3");
    else
      T_OK();
  }

  vll_destroy(mgr);
}

/* ════════════════════════════════════════════════════════════════
 * MODULO 3 — CRDT
 * ══════════════════════════════════════════════════════════════ */
static void test_crdt(void) {
  printf("\n── CRDT Tests ──────────────────────────────────────────\n");

  T_START("CRDT GCounter: increment + merge");
  {
    GCounter *g1 = gcounter_create(0, 3);
    GCounter *g2 = gcounter_create(1, 3);
    gcounter_increment(g1, 5);
    gcounter_increment(g2, 3);
    gcounter_merge(g1, g2);
    uint64_t v = gcounter_value(g1);
    gcounter_destroy(g1);
    gcounter_destroy(g2);
    if (v != 8)
      T_FAIL("expected 8");
    else
      T_OK();
  }

  T_START("CRDT GCounter: merge is idempotent");
  {
    GCounter *g1 = gcounter_create(0, 2);
    GCounter *g2 = gcounter_create(1, 2);
    gcounter_increment(g1, 10);
    gcounter_increment(g2, 7);
    gcounter_merge(g1, g2);
    uint64_t v1 = gcounter_value(g1);
    gcounter_merge(g1, g2);
    uint64_t v2 = gcounter_value(g1);
    gcounter_destroy(g1);
    gcounter_destroy(g2);
    if (v1 != v2)
      T_FAIL("not idempotent");
    else
      T_OK();
  }

  T_START("CRDT PNCounter: increment + decrement");
  {
    PNCounter *p = pncounter_create(0, 1);
    pncounter_increment(p, 100);
    pncounter_decrement(p, 30);
    int64_t v = pncounter_value(p);
    pncounter_destroy(p);
    if (v != 70)
      T_FAIL("expected 70");
    else
      T_OK();
  }

  T_START("CRDT PNCounter: merge two nodes");
  {
    PNCounter *p1 = pncounter_create(0, 2);
    PNCounter *p2 = pncounter_create(1, 2);
    pncounter_increment(p1, 50);
    pncounter_increment(p2, 30);
    pncounter_decrement(p1, 10);
    pncounter_merge(p1, p2);
    int64_t v = pncounter_value(p1);
    pncounter_destroy(p1);
    pncounter_destroy(p2);
    if (v != 70)
      T_FAIL("expected 70");
    else
      T_OK();
  }

  T_START("CRDT ORSet: add + contains");
  {
    ORSet *s = orset_create(0);
    const uint8_t *m = (const uint8_t *)"user:alice";
    orset_add(s, m, 10);
    int ok = orset_contains(s, m, 10) && orset_size(s) == 1;
    orset_destroy(s);
    if (!ok)
      T_FAIL("contains failed");
    else
      T_OK();
  }

  T_START("CRDT ORSet: remove observed tags");
  {
    ORSet *s = orset_create(0);
    const uint8_t *m = (const uint8_t *)"user:bob";
    orset_add(s, m, 8);
    orset_remove(s, m, 8);
    int ok = !orset_contains(s, m, 8);
    orset_destroy(s);
    if (!ok)
      T_FAIL("still present");
    else
      T_OK();
  }

  T_START("CRDT ORSet: concurrent add merge correctly");
  {
    ORSet *s1 = orset_create(0);
    ORSet *s2 = orset_create(1);
    orset_add(s1, (const uint8_t *)"a", 1);
    orset_add(s2, (const uint8_t *)"b", 1);
    orset_merge(s1, s2);
    int ok = orset_contains(s1, (const uint8_t *)"a", 1) &&
             orset_contains(s1, (const uint8_t *)"b", 1) && orset_size(s1) == 2;
    orset_destroy(s1);
    orset_destroy(s2);
    if (!ok)
      T_FAIL("merge wrong");
    else
      T_OK();
  }

  T_START("CRDT LWWRegister: set + get");
  {
    LWWRegister *r = lww_create(0, 2);
    lww_set(r, (const uint8_t *)"hello", 5);
    uint8_t buf[64];
    uint16_t len = lww_get(r, buf, sizeof(buf));
    int ok = (len == 5) && (memcmp(buf, "hello", 5) == 0);
    lww_destroy(r);
    if (!ok)
      T_FAIL("value mismatch");
    else
      T_OK();
  }

  T_START("CRDT LWWRegister: merge keeps latest timestamp");
  {
    LWWRegister *r1 = lww_create(0, 2);
    LWWRegister *r2 = lww_create(1, 2);
    lww_set(r1, (const uint8_t *)"old", 3);
    usleep(5000);
    lww_set(r2, (const uint8_t *)"new", 3);
    lww_merge(r1, r2);
    uint8_t buf[32];
    lww_get(r1, buf, sizeof(buf));
    int ok = memcmp(buf, "new", 3) == 0;
    lww_destroy(r1);
    lww_destroy(r2);
    if (!ok)
      T_FAIL("LWW kept old");
    else
      T_OK();
  }
}

/* ════════════════════════════════════════════════════════════════
 * MODULO 4 — Subkey TTL
 * ══════════════════════════════════════════════════════════════ */
static int sk_expire_count = 0;
static void on_sk_expire(const char *pk, const uint8_t *f, uint8_t fl,
                         SubkeyContainerType t, void *ctx) {
  (void)pk;
  (void)f;
  (void)fl;
  (void)t;
  (void)ctx;
  sk_expire_count++;
}

static void test_subkey_ttl(void) {
  printf("\n── Subkey TTL Tests ─────────────────────────────────────\n");

  T_START("SubkeyTTL: create Hash TTL storage");
  {
    SubkeyTTL *s = subkey_ttl_create("user:123", SKC_HASH);
    int ok = s != NULL;
    if (s)
      subkey_ttl_destroy(s);
    if (!ok)
      T_FAIL("create failed");
    else
      T_OK();
  }

  T_START("SubkeyTTL: set + get field TTL");
  {
    SubkeyTTL *s = subkey_ttl_create("user:123", SKC_HASH);
    uint32_t future = (uint32_t)time(NULL) + 3600;
    const uint8_t *f = (const uint8_t *)"token";
    int ok = s && (subkey_ttl_set(s, f, 5, future) == 0) &&
             (subkey_ttl_get(s, f, 5) == future);
    if (s)
      subkey_ttl_destroy(s);
    if (!ok)
      T_FAIL("TTL mismatch");
    else
      T_OK();
  }

  T_START("SubkeyTTL: clear field TTL");
  {
    SubkeyTTL *s = subkey_ttl_create("h", SKC_HASH);
    uint32_t future = (uint32_t)time(NULL) + 600;
    const uint8_t *f = (const uint8_t *)"field1";
    subkey_ttl_set(s, f, 6, future);
    int ok = (subkey_ttl_clear(s, f, 6) == 1) && (subkey_ttl_get(s, f, 6) == 0);
    subkey_ttl_destroy(s);
    if (!ok)
      T_FAIL("clear failed");
    else
      T_OK();
  }

  T_START("SubkeyTTL: expire removes past entries");
  {
    sk_expire_count = 0;
    SubkeyTTL *s = subkey_ttl_create("myhash", SKC_HASH);
    uint32_t past = (uint32_t)time(NULL) - 1;
    uint32_t future = (uint32_t)time(NULL) + 600;
    subkey_ttl_set(s, (const uint8_t *)"old_f", 5, past);
    subkey_ttl_set(s, (const uint8_t *)"new_f", 5, future);
    int expired = subkey_ttl_expire(s, on_sk_expire, NULL);
    int ok = (expired == 1) && (sk_expire_count == 1) &&
             (subkey_ttl_active_count(s) == 1u);
    subkey_ttl_destroy(s);
    if (!ok)
      T_FAIL("expire wrong");
    else
      T_OK();
  }

  T_START("SubkeyTTL: supports Set/ZSet/List/Vector types");
  {
    SubkeyContainerType types[] = {SKC_SET, SKC_ZSET, SKC_LIST, SKC_VECTOR};
    int ok = 1;
    for (int i = 0; i < 4 && ok; i++) {
      SubkeyTTL *s = subkey_ttl_create("key", types[i]);
      if (!s) {
        ok = 0;
        break;
      }
      uint32_t f = (uint32_t)time(NULL) + 60;
      subkey_ttl_set(s, (const uint8_t *)"m", 1, f);
      if (subkey_ttl_get(s, (const uint8_t *)"m", 1) != f)
        ok = 0;
      subkey_ttl_destroy(s);
    }
    if (!ok)
      T_FAIL("container type fail");
    else
      T_OK();
  }
}

/* ════════════════════════════════════════════════════════════════
 * MODULO 5 — NexSegcache
 * ══════════════════════════════════════════════════════════════ */
static void test_segcache(void) {
  printf("\n── NexSegcache Tests (Pelikan NSDI'21) ─────────────────\n");
  NexSegcache *sc = segcache_create(16 * 1024 * 1024, 256 * 1024);

  T_START("Segcache: create 16MB");
  if (!sc) {
    T_FAIL("NULL");
    return;
  }
  T_OK();

  T_START("Segcache: set + get");
  {
    const char *key = "greeting", *val = "ciao";
    int rc = segcache_set(sc, key, (uint16_t)strlen(key), (const uint8_t *)val,
                          (uint16_t)strlen(val), 3600);
    uint8_t buf[64];
    uint16_t vlen = 0;
    int rc2 =
        segcache_get(sc, key, (uint16_t)strlen(key), buf, sizeof(buf), &vlen);
    int ok =
        (rc == 0) && (rc2 == 0) && (vlen == 4) && (memcmp(buf, val, 4) == 0);
    if (!ok)
      T_FAIL("set/get failed");
    else
      T_OK();
  }

  T_START("Segcache: write 1000 objects with TTL");
  {
    char kb[32], vb[64];
    int ok = 1;
    for (int i = 0; i < 1000 && ok; i++) {
      snprintf(kb, sizeof(kb), "sk:%05d", i);
      snprintf(vb, sizeof(vb), "value_%05d", i);
      if (segcache_set(sc, kb, (uint16_t)strlen(kb), (const uint8_t *)vb,
                       (uint16_t)strlen(vb), 3600 + i) != 0)
        ok = 0;
    }
    if (!ok)
      T_FAIL("bulk write failed");
    else
      T_OK();
  }

  T_START("Segcache: exists");
  {
    /* "greeting" was written with TTL=3600 in same seg bucket as sk:00000
     * (TTL=3600) */
    int e1 = segcache_exists(sc, "greeting", 8);
    int e2 = segcache_exists(sc, "notexist", 8);
    if (e1 != 1 || e2 != 0)
      T_FAIL("exists wrong");
    else
      T_OK();
  }

  T_START("Segcache: delete key");
  {
    int d = segcache_del(sc, "greeting", 8);
    int e = segcache_exists(sc, "greeting", 8);
    if (d != 1 || e != 0)
      T_FAIL("del failed");
    else
      T_OK();
  }

  T_START("Segcache: stats populated");
  {
    SegStats s = segcache_get_stats(sc);
    if (s.sets < 1001 || s.hits == 0)
      T_FAIL("stats wrong");
    else
      T_OK();
  }

  segcache_destroy(sc);
}

/* ════════════════════════════════════════════════════════════════
 * MODULO 6 — NexStorage Narrow-Waist API
 * ══════════════════════════════════════════════════════════════ */
static void test_nexstorage(void) {
  printf("\n── NexStorage Narrow-Waist API Tests ───────────────────\n");

  T_START("NexStorage: create with NexDashTable backend");
  NexStorage *ns = nexstorage_create("nexdash", "max_memory=32000000");
  if (!ns) {
    T_FAIL("NULL");
    return;
  }
  T_OK();

  T_START("NexStorage: get non-existent key returns NOT_FOUND");
  {
    NexEntry e = {0};
    NexStorageResult rc = nexstorage_get(ns, "nokey", 5, &e);
    if (rc != NEXS_NOT_FOUND)
      T_FAIL("expected NOT_FOUND");
    else
      T_OK();
  }

  T_START("NexStorage: set + get round-trip");
  {
    const uint8_t *val = (const uint8_t *)"nexcache_is_fast";
    NexStorageResult rc =
        nexstorage_set(ns, "speed", 5, val, 16, NEXDT_STRING, -1);
    NexEntry e = {0};
    NexStorageResult rc2 = nexstorage_get(ns, "speed", 5, &e);
    int ok = (rc == NEXS_OK) && (rc2 == NEXS_OK) && (e.value_len == 16);
    if (!ok)
      T_FAIL("round-trip failed");
    else
      T_OK();
  }

  T_START("NexStorage: delete key");
  {
    nexstorage_set(ns, "delme", 5, (const uint8_t *)"x", 1, NEXDT_STRING, -1);
    NexStorageResult d = nexstorage_del(ns, "delme", 5);
    NexEntry e = {0};
    NexStorageResult r = nexstorage_get(ns, "delme", 5, &e);
    if (d != NEXS_OK || r != NEXS_NOT_FOUND)
      T_FAIL("del failed");
    else
      T_OK();
  }

  T_START("NexStorage: create with Segcache backend");
  {
    NexStorage *nsc = nexstorage_create("segcache", "max_memory=8000000");
    int ok = nsc != NULL;
    if (ok) {
      nexstorage_set(nsc, "segkey", 6, (const uint8_t *)"segval", 6,
                     NEXDT_STRING, 60000);
      NexEntry e = {0};
      ok = (nexstorage_get(nsc, "segkey", 6, &e) == NEXS_OK);
      nexstorage_destroy(nsc);
    }
    if (!ok)
      T_FAIL("segcache backend failed");
    else
      T_OK();
  }

  nexstorage_destroy(ns);
}

/* ════════════════════════════════════════════════════════════════
 * MODULO 7 — Anomaly Detection
 * ══════════════════════════════════════════════════════════════ */
static int anomaly_alerts = 0;
static void on_anomaly(const AnomalyEvent *ev, void *ctx) {
  (void)ev;
  (void)ctx;
  anomaly_alerts++;
}

static void test_anomaly(void) {
  printf("\n── Anomaly Detection Tests ─────────────────────────────\n");
  AnomalyDetector *d = anomaly_create(NULL, on_anomaly, NULL);

  T_START("Anomaly: create detector with default config");
  if (!d) {
    T_FAIL("NULL");
    return;
  }
  T_OK();

  T_START("Anomaly: update metrics API works");
  {
    anomaly_update_latency(d, 150.0);
    anomaly_update_memory(d, 100 * 1024 * 1024);
    anomaly_update_evictions(d, 50);
    anomaly_update_connections(d, 100);
    anomaly_update_errors(d, 0.5);
    anomaly_record_key_access(d, "user:123");
    T_OK(); /* No crash = OK */
  }

  T_START("Anomaly: hot key tracking via Count-Min Sketch");
  {
    for (int i = 0; i < 50; i++)
      anomaly_record_key_access(d, "hot_key:viral");
    int ok = d->hot_key_tracker.top_count >= 50;
    if (!ok)
      T_FAIL("count too low");
    else
      T_OK();
  }

  T_START("Anomaly: JSON export");
  {
    char buf[512];
    int n = anomaly_export_json(d, buf, sizeof(buf));
    int ok = (n > 0) && (strstr(buf, "total_anomalies") != NULL);
    if (!ok)
      T_FAIL("export wrong");
    else
      T_OK();
  }

  anomaly_destroy(d);
}

/* ════════════════════════════════════════════════════════════════
 * MAIN
 * ══════════════════════════════════════════════════════════════ */
int main(void) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════╗\n");
  printf("║    NexCache v4.0 — Test Suite Completa                  ║\n");
  printf("║    SuperPrompt v4.0: NexDash·VLL·CRDT·Segcache·Storage ║\n");
  printf("╚══════════════════════════════════════════════════════════╝\n");

  test_nexdash();
  test_vll();
  test_crdt();
  test_subkey_ttl();
  test_segcache();
  test_nexstorage();
  test_anomaly();

  printf("\n");
  printf("╔══════════════════════════════════════════════╗\n");
  printf("║  RISULTATI FINALI                            ║\n");
  printf("╠══════════════════════════════════════════════╣\n");
  printf("║  Test eseguiti:  %3d                         ║\n", tests_run);
  printf("║  Test passati:   %3d ✅                      ║\n", tests_passed);
  printf("║  Test falliti:   %3d %s                      ║\n", tests_failed,
         tests_failed > 0 ? "❌" : "  ");
  printf("╚══════════════════════════════════════════════╝\n\n");

  if (tests_failed > 0) {
    printf("❌  %d TEST FALLITI\n", tests_failed);
    return 1;
  }
  printf("✅  TUTTI I %d TEST PASSATI — NexCache v4.0 OK!\n", tests_passed);
  return 0;
}
