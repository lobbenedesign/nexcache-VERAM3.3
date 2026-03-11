# NexCache Makefile — v2.1
# ============================================================
CC      ?= gcc
# Usiamo += per permettere a GitHub Actions di aggiungere flag hardware
CFLAGS  += -O3 -std=c11 -Wall -Wextra -pthread -D_GNU_SOURCE \
            -Isrc -Isrc/memory -Isrc/core -Isrc/vector -Isrc/hashtable \
            -Isrc/segcache -Isrc/crdt -Isrc/bloom -Isrc/network -Isrc/security

UNAME_S := $(shell uname -s)
LDFLAGS += -lpthread -lm
ifneq ($(UNAME_S),Darwin)
    LDFLAGS += -lrt
endif

BUILD_DIR := build
SRC_DIR   := src
TEST_DIR  := tests

# --- TUTTI I MODULI NEXCACHE ---
SRCS_MEMORY := $(SRC_DIR)/memory/arena.c $(SRC_DIR)/memory/hybrid.c $(SRC_DIR)/memory/arch_probe.c $(SRC_DIR)/memory/hazard_ptr.c
SRCS_CORE   := $(SRC_DIR)/core/engine.c $(SRC_DIR)/core/scheduler.c $(SRC_DIR)/core/vll.c $(SRC_DIR)/core/subkey_ttl.c $(SRC_DIR)/core/nexstorage.c $(SRC_DIR)/core/planes.c
SRCS_HASH   := $(SRC_DIR)/hashtable/nexdash.c $(SRC_DIR)/segcache/segcache.c
SRCS_CRDT   := $(SRC_DIR)/crdt/crdt.c $(SRC_DIR)/bloom/nexbloom.c
SRCS_VECTOR := $(SRC_DIR)/vector/quantization.c $(SRC_DIR)/vector/router.c $(SRC_DIR)/vector/hnsw.c
SRCS_NET    := $(SRC_DIR)/network/protocol_detect.c $(SRC_DIR)/network/websocket.c
SRCS_SEC    := $(SRC_DIR)/security/quota.c

ALL_SRCS := $(SRCS_MEMORY) $(SRCS_CORE) $(SRCS_HASH) $(SRCS_CRDT) $(SRCS_VECTOR) $(SRCS_NET) $(SRCS_SEC)
OBJS     := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(ALL_SRCS))

LIB  := $(BUILD_DIR)/libnexcache.a
TESTS := $(BUILD_DIR)/test_arena $(BUILD_DIR)/test_core_v2 $(BUILD_DIR)/test_v4

.PHONY: all clean test dirs banner

all: banner dirs $(LIB) $(TESTS)
	@echo "✅ NexCache v1.0 build COMPLETO"

banner:
	@echo "╔══════════════════════════════════════════╗"
	@echo "║   NexCache — Professional Build System   ║"
	@echo "╚══════════════════════════════════════════╝"
	@echo "  OS: $(UNAME_S)"

dirs:
	@mkdir -p $(BUILD_DIR)/memory $(BUILD_DIR)/core $(BUILD_DIR)/vector \
	           $(BUILD_DIR)/hashtable $(BUILD_DIR)/segcache $(BUILD_DIR)/crdt \
	           $(BUILD_DIR)/bloom $(BUILD_DIR)/network $(BUILD_DIR)/security

$(LIB): $(OBJS)
	@echo "  [AR]  $@"
	@ar rcs $@ $(OBJS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "  [CC]  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Test Targets
$(BUILD_DIR)/test_%: $(TEST_DIR)/test_%.c $(LIB)
	@echo "  [LD]  $@"
	@$(CC) $(CFLAGS) $< -o $@ -L$(BUILD_DIR) -lnexcache $(LDFLAGS)

clean:
	@rm -rf $(BUILD_DIR)
