# NexCache Makefile — v2.0
# ============================================================
# Compila tutti i moduli NexCache che hanno un .c implementato.
# Non dipende da Valkey — build standalone dei moduli.
#
# Uso:
#   make             → Compila libreria + test + benchmarks
#   make test        → Esegui tutti i test
#   make clean       → Pulisci build artifacts
#   make info        → Mostra stato implementazione
#
# Dipendenze opzionali:
#   LZ4:    apt-get install liblz4-dev     (macOS: brew install lz4)
#   Zstd:   apt-get install libzstd-dev    (macOS: brew install zstd)
# ============================================================

CC      ?= gcc
CFLAGS  := -O2 -std=c11 -Wall -Wextra -Wpedantic \
            -pthread -D_GNU_SOURCE \
            -Isrc -Isrc/memory -Isrc/core -Isrc/vector \
            -Isrc/ai -Isrc/network -Isrc/security \
            -Isrc/compression -Isrc/wasm -Isrc/consensus \
            -Isrc/streams -Isrc/observability \
            -Isrc/persistence -Isrc/cluster

# Aggiungi -fsanitize=address per debug memory issues
ifdef ASAN
CFLAGS += -fsanitize=address,undefined -g3
endif

# Aggiungi -pg per profiling
ifdef PROFILE
CFLAGS += -pg -g
endif

# Rileva sistema operativo per link flags
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LDFLAGS    := -lpthread -lm
    LDFLAGS_LZ4 := -llz4
    LDFLAGS_ZSTD := -lzstd
else
    LDFLAGS    := -lpthread -lm -lrt
    LDFLAGS_LZ4 := -llz4
    LDFLAGS_ZSTD := -lzstd
endif

# Detection architettura per ottimizzazioni SIMD x86
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    VEC_FLAGS := -msse4.1 -mavx2
endif

# Rilevamento automatico LZ4 e Zstd
LZ4_AVAILABLE  := $(shell pkg-config --exists liblz4  2>/dev/null && echo yes || echo no)
ZSTD_AVAILABLE := $(shell pkg-config --exists libzstd 2>/dev/null && echo yes || echo no)

ifeq ($(LZ4_AVAILABLE),yes)
    CFLAGS  += -DHAVE_LZ4 $(shell pkg-config --cflags liblz4)
    LDFLAGS += $(shell pkg-config --libs liblz4)
endif
ifeq ($(ZSTD_AVAILABLE),yes)
    CFLAGS  += -DHAVE_ZSTD $(shell pkg-config --cflags libzstd)
    LDFLAGS += $(shell pkg-config --libs libzstd)
endif

# ── Directory ───────────────────────────────────────────────
BUILD_DIR := build
SRC_DIR   := src
TEST_DIR  := tests
BENCH_DIR := benchmarks

# ── Sorgenti — Moduli implementati (header + .c) ────────────
SRCS_MEMORY := \
    $(SRC_DIR)/memory/arena.c \
    $(SRC_DIR)/memory/hybrid.c \
    $(SRC_DIR)/memory/arch_probe.c \
    $(SRC_DIR)/memory/hazard_ptr.c

SRCS_CORE := \
    $(SRC_DIR)/core/engine.c \
    $(SRC_DIR)/core/scheduler.c \
    $(SRC_DIR)/bloom/nexbloom.c

SRCS_VECTOR := \
    $(SRC_DIR)/vector/router.c \
    $(SRC_DIR)/vector/quantization.c \
    $(SRC_DIR)/vector/hnsw.c

SRCS_AI := \
    $(SRC_DIR)/ai/semantic.c

SRCS_NETWORK := \
    $(SRC_DIR)/network/websocket.c \
    $(SRC_DIR)/network/protocol_detect.c

SRCS_SECURITY := \
    $(SRC_DIR)/security/quota.c \
    $(SRC_DIR)/security/pqcrypto.c

SRCS_COMPRESSION := \
    $(SRC_DIR)/compression/auto.c

SRCS_WASM := \
    $(SRC_DIR)/wasm/runtime.c

SRCS_CONSENSUS := \
    $(SRC_DIR)/consensus/raft.c

SRCS_STREAMS := \
    $(SRC_DIR)/streams/reactive.c

SRCS_OBS := \
    $(SRC_DIR)/observability/otel.c \
    $(SRC_DIR)/observability/dashboard.c

SRCS_PERSIST := \
    $(SRC_DIR)/persistence/persist.c

SRCS_CLUSTER := \
    $(SRC_DIR)/cluster/cluster.c

SRCS_HASHTABLE := \
    $(SRC_DIR)/hashtable/nexdash.c

SRCS_SEGCACHE := \
    $(SRC_DIR)/segcache/segcache.c

SRCS_CRDT := \
    $(SRC_DIR)/crdt/crdt.c

SRCS_FLASH := \
    $(SRC_DIR)/flash/flash.c

SRCS_CORE_V4 := \
    $(SRC_DIR)/core/vll.c \
    $(SRC_DIR)/core/subkey_ttl.c \
    $(SRC_DIR)/core/nexstorage.c \
    $(SRC_DIR)/core/planes.c

SRCS_CLOUD := \
    $(SRC_DIR)/cloud_tier/cloud.c

SRCS_NET_V4 := \
    $(SRC_DIR)/network/dpdk_net.c \
    $(SRC_DIR)/network/io_uring_net.c

SRCS_OBS_V4 := \
    $(SRC_DIR)/observability/anomaly.c

# Tutti i sorgenti uniti (v4)
ALL_SRCS := $(SRCS_MEMORY) $(SRCS_CORE) $(SRCS_VECTOR) $(SRCS_AI) \
             $(SRCS_NETWORK) $(SRCS_SECURITY) $(SRCS_COMPRESSION) \
             $(SRCS_WASM) $(SRCS_CONSENSUS) $(SRCS_STREAMS) $(SRCS_OBS) \
             $(SRCS_PERSIST) $(SRCS_CLUSTER) \
             $(SRCS_HASHTABLE) $(SRCS_SEGCACHE) $(SRCS_CRDT) \
             $(SRCS_FLASH) $(SRCS_CORE_V4) $(SRCS_OBS_V4) \
             $(SRCS_CLOUD) $(SRCS_NET_V4)

# Object files
ALL_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(ALL_SRCS))

# ── Libreria statica ────────────────────────────────────────
LIBRARY := $(BUILD_DIR)/libnexcache.a

# ── Test target ──────────────────────────────────────────────
TEST_ARENA    := $(BUILD_DIR)/test_arena
TEST_CORE_V2  := $(BUILD_DIR)/test_core_v2
TEST_ADVANCED := $(BUILD_DIR)/test_advanced
TEST_V4       := $(BUILD_DIR)/test_v4

# ── Default target ───────────────────────────────────────────
.PHONY: all clean test info dirs banner

all: banner dirs $(LIBRARY) tests
	@echo ""
	@echo "✅  NexCache v4.0 build COMPLETO"
	@echo "    Libreria:  $(LIBRARY)"
	@echo "    Test:      $(TEST_ARENA) $(TEST_CORE_V2) $(TEST_ADVANCED) $(TEST_V4)"
	@echo "    Usa 'make test' per eseguire i test"

banner:
	@echo "╔══════════════════════════════════════════╗"
	@echo "║   NexCache — Build System v2.0           ║"
	@echo "║   Base: Valkey 9.0.3 (fork)              ║"
	@echo "╚══════════════════════════════════════════╝"
	@echo "  LZ4:  $(LZ4_AVAILABLE)"
	@echo "  Zstd: $(ZSTD_AVAILABLE)"
	@echo "  OS:   $(UNAME_S)"

dirs:
	@mkdir -p $(BUILD_DIR)/memory $(BUILD_DIR)/core $(BUILD_DIR)/vector \
	           $(BUILD_DIR)/ai $(BUILD_DIR)/network $(BUILD_DIR)/security \
	           $(BUILD_DIR)/compression $(BUILD_DIR)/wasm $(BUILD_DIR)/consensus \
	           $(BUILD_DIR)/streams $(BUILD_DIR)/observability \
	           $(BUILD_DIR)/persistence $(BUILD_DIR)/cluster \
	           $(BUILD_DIR)/hashtable $(BUILD_DIR)/segcache \
	           $(BUILD_DIR)/crdt $(BUILD_DIR)/flash $(BUILD_DIR)/cloud_tier \
	           $(BUILD_DIR)/bloom

# ── Libreria statica ─────────────────────────────────────────
$(LIBRARY): $(ALL_OBJS)
	@echo "  [AR]  $@"
	@ar rcs $@ $^

# ── Regola specifica per Quantization (permette x86 in GitHub Actions) ─
$(BUILD_DIR)/vector/quantization.o: $(SRC_DIR)/vector/quantization.c
	@echo "  [CC]  $< (Hardware optimized)"
	@$(CC) $(CFLAGS) $(VEC_FLAGS) -c $< -o $@

# ── Regola generica .c → .o ──────────────────────────────────
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "  [CC]  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# ── Test targets ─────────────────────────────────────────────
tests: $(TEST_ARENA) $(TEST_CORE_V2) $(TEST_ADVANCED) $(TEST_V4)

$(TEST_ARENA): $(TEST_DIR)/test_arena.c $(LIBRARY)
	@echo "  [LD]  $@"
	@$(CC) $(CFLAGS) $< -o $@ -L$(BUILD_DIR) -lnexcache $(LDFLAGS)

$(TEST_CORE_V2): $(TEST_DIR)/test_core_v2.c $(LIBRARY)
	@echo "  [LD]  $@"
	@$(CC) $(CFLAGS) $< -o $@ -L$(BUILD_DIR) -lnexcache $(LDFLAGS)

$(TEST_ADVANCED): $(TEST_DIR)/test_advanced.c $(LIBRARY)
	@echo "  [LD]  $@"
	@$(CC) $(CFLAGS) $< -o $@ -L$(BUILD_DIR) -lnexcache $(LDFLAGS) -lm

$(TEST_V4): $(TEST_DIR)/test_v4.c $(LIBRARY)
	@echo "  [LD]  $@"
	@$(CC) $(CFLAGS) $< -o $@ -L$(BUILD_DIR) -lnexcache $(LDFLAGS) -lm

# ── Esecuzione test ──────────────────────────────────────────
test: all
	@echo ""
	@echo "╔══════ Esecuzione Test Suite ══════╗"
	@echo "Running: test_arena..."
	@$(TEST_ARENA) && echo "  → PASS" || echo "  → FAIL"
	@echo ""
	@echo "Running: test_core_v2..."
	@$(TEST_CORE_V2) && echo "  → PASS" || echo "  → FAIL"
	@echo ""
	@echo "Running: test_advanced..."
	@$(TEST_ADVANCED) && echo "  → PASS" || echo "  → FAIL"
	@echo ""
	@echo "Running: test_v4 (NexCache v4 modules)..."
	@$(TEST_V4) && echo "  → PASS" || echo "  → FAIL"
	@echo "╚════════════════════════════════════╝"

# ── Info sullo stato implementazione ─────────────────────────
info:
	@echo "╔══════════════════════════════════════════╗"
	@echo "║   NexCache Implementation Status v2.0    ║"
	@echo "╠══════════════════════════════════════════╣"
	@echo "  Headers implementati:"
	@find src -name "*.h" | sort | awk '{print "    ✅ " $$1}'
	@echo ""
	@echo "  C files implementati:"
	@find src -name "*.c" | sort | awk '{print "    ✅ " $$1}'
	@echo ""
	@echo "  Test files:"
	@find tests -name "*.c" | sort | awk '{print "    🧪 " $$1}'
	@echo "╚══════════════════════════════════════════╝"

# ── Benchmark ────────────────────────────────────────────────
bench:
	@echo "Running benchmarks..."
	@chmod +x $(BENCH_DIR)/compare.sh
	@$(BENCH_DIR)/compare.sh quick

# ── Pulizia ──────────────────────────────────────────────────
clean:
	@echo "  [RM]  $(BUILD_DIR)/"
	@rm -rf $(BUILD_DIR)

# ── Formattazione codice (richiede clang-format) ─────────────
format:
	@find src tests -name "*.c" -o -name "*.h" | \
	    xargs clang-format -i --style="{BasedOnStyle: LLVM, IndentWidth: 4}"

# ── Analisi statica (richiede cppcheck) ──────────────────────
analysis:
	@cppcheck --enable=all --std=c11 \
	    --suppress=missingIncludeSystem \
	    src/ 2>&1 | grep -E "error|warning" | head -50

# ── Generazione compile_commands.json per IDEs ───────────────
compile_commands:
	@bear -- make all
	@echo "compile_commands.json generato per LSP/IDE"

.PHONY: all clean test bench info format analysis compile_commands
