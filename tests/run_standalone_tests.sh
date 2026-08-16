#!/usr/bin/env bash
# NexCache — Runner per la suite di test standalone (tests/*.c)
# ============================================================
# Compila e lancia tutti i test standalone del progetto, in build
# normale E sotto ThreadSanitizer (dove applicabile) per i test di
# concorrenza. Pensato per essere lanciato prima di ogni merge o
# valutazione seria del motore — non sostituisce un benchmark, ma
# verifica la correttezza dei moduli fixati.
#
# Uso:
#   ./tests/run_standalone_tests.sh          # tutti i test
#   ./tests/run_standalone_tests.sh --tsan   # solo la suite di concorrenza sotto TSan
#
# Copyright (c) 2026 NexCache Project — BSD License

set -u
cd "$(dirname "$0")/.." || exit 1
SRC=src
BUILD=/tmp/nexcache_test_build
mkdir -p "$BUILD"

CC=${CC:-clang}
PASS=0
FAIL=0
FAILED_NAMES=()

run_one() {
    local name="$1"
    local bin="$BUILD/$name"
    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  $name"
    echo "════════════════════════════════════════════════════════"
    if "$bin"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("$name")
    fi
}

build_and_run() {
    local name="$1"; shift
    echo "[build] $name"
    if ! "$CC" -O1 -g -o "$BUILD/$name" "$@" -I "$SRC" -lpthread -lm 2>"$BUILD/$name.build.log"; then
        echo "  BUILD FAILED — vedi $BUILD/$name.build.log"
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("$name (build)")
        return
    fi
    run_one "$name"
}

TSAN_ONLY=0
if [ "${1:-}" = "--tsan" ]; then TSAN_ONLY=1; fi

if [ "$TSAN_ONLY" -eq 0 ]; then
    # ── Suite esistenti (moduli nel Makefile: usa i .o già compilati con `make`) ──
    build_and_run test_v4 tests/test_v4.c \
        "$SRC/core/nexstorage.o" "$SRC/core/vll.o" "$SRC/core/subkey_ttl.o" \
        "$SRC/hashtable/nexdash.o" "$SRC/bloom/nexbloom.o" "$SRC/memory/arena.o" \
        "$SRC/crdt/crdt.o" "$SRC/segcache/segcache.o" "$SRC/flash/flash.o" \
        "$SRC/observability/anomaly.o" "$SRC/macos_stubs.o"

    build_and_run test_core_v2 tests/test_core_v2.c \
        "$SRC/network/protocol_detect.o" "$SRC/network/websocket.o" "$SRC/memory/arch_probe.o"

    echo "[build] test_arena"
    if ! "$CC" -O2 -o "$BUILD/test_arena" tests/test_arena.c "$SRC/memory/arena.o" \
        -I "$SRC" -I "$SRC/memory" -lpthread -lm 2>"$BUILD/test_arena.build.log"; then
        echo "  BUILD FAILED — vedi $BUILD/test_arena.build.log"
        FAIL=$((FAIL + 1))
        FAILED_NAMES+=("test_arena (build)")
    else
        run_one test_arena
    fi

    # test_advanced.c copre moduli FUORI dal Makefile (persist.c, pqcrypto.c,
    # cluster.c) — compilati direttamente dal sorgente, non dai .o.
    build_and_run test_advanced tests/test_advanced.c \
        "$SRC/cluster/cluster.c" "$SRC/persistence/persist.c" "$SRC/security/pqcrypto.c" \
        "$SRC/vector/hnsw.o" "$SRC/vector/quantization.o"

    build_and_run test_concurrency tests/test_concurrency_20260807.c \
        "$SRC/core/nexstorage.o" "$SRC/core/vll.o" "$SRC/hashtable/nexdash.o" \
        "$SRC/bloom/nexbloom.o" "$SRC/memory/arena.o" "$SRC/segcache/segcache.o" \
        "$SRC/flash/flash.o" "$SRC/macos_stubs.o"
fi

# ── Build TSan della suite di concorrenza (dal sorgente, non dai .o:
#    serve che OGNI file sia instrumentato, .o pre-compilati senza
#    -fsanitize=thread non basterebbero) ──
echo ""
echo "[build] test_concurrency_tsan (ThreadSanitizer)"
if clang -O1 -g -fsanitize=thread -o "$BUILD/test_concurrency_tsan" \
    tests/test_concurrency_20260807.c \
    "$SRC/core/nexstorage.c" "$SRC/core/vll.c" "$SRC/hashtable/nexdash.c" \
    "$SRC/bloom/nexbloom.c" "$SRC/memory/arena.c" "$SRC/segcache/segcache.c" \
    "$SRC/flash/flash.c" "$SRC/macos_stubs.c" \
    -I "$SRC" -lpthread -lm 2>"$BUILD/test_concurrency_tsan.build.log"; then
    TSAN_OPTIONS="halt_on_error=0" run_one test_concurrency_tsan
else
    echo "  BUILD FAILED — vedi $BUILD/test_concurrency_tsan.build.log"
    FAIL=$((FAIL + 1))
    FAILED_NAMES+=("test_concurrency_tsan (build)")
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  RIEPILOGO: $PASS suite passate, $FAIL fallite"
if [ "$FAIL" -gt 0 ]; then
    echo "  Fallite: ${FAILED_NAMES[*]}"
fi
echo "════════════════════════════════════════════════════════"

exit $((FAIL > 0 ? 1 : 0))
