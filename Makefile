# NexCache Makefile — v2.6 (Gold Release)
# ============================================================
CC      ?= gcc

# Configuriamo le CFLAGS qui, in modo che siano protette
CFLAGS  := -O3 -std=c11 -Wall -Wextra -pthread -D_GNU_SOURCE \
            -Isrc -Isrc/memory -Isrc/core -Isrc/vector -Isrc/hashtable \
            -Isrc/segcache -Isrc/crdt -Isrc/bloom -Isrc/network -Isrc/security

UNAME_S := $(shell uname -s)
ARCH    := $(shell uname -m)

LDFLAGS := -lpthread -lm
ifneq ($(UNAME_S),Darwin)
    LDFLAGS += -lrt
endif

# Forziamo Haswell su sistemi x86_64 (GitHub CI)
ifeq ($(ARCH),x86_64)
    CFLAGS += -march=haswell
endif

# Flags SIMD specifici per quantization.o
SIMD_FLAGS := 
ifeq ($(ARCH),x86_64)
    SIMD_FLAGS := -msse4.1 -mavx2 -mfma
endif

BUILD_DIR := build
SRC_DIR   := src
TEST_DIR  := tests

SRCS := $(SRC_DIR)/memory/arena.c \
        $(SRC_DIR)/memory/hybrid.c \
        $(SRC_DIR)/memory/arch_probe.c \
        $(SRC_DIR)/memory/hazard_ptr.c \
        $(SRC_DIR)/core/engine.c \
        $(SRC_DIR)/core/scheduler.c \
        $(SRC_DIR)/core/vll.c \
        $(SRC_DIR)/core/subkey_ttl.c \
        $(SRC_DIR)/core/nexstorage.c \
        $(SRC_DIR)/core/planes.c \
        $(SRC_DIR)/hashtable/nexdash.c \
        $(SRC_DIR)/segcache/segcache.c \
        $(SRC_DIR)/crdt/crdt.c \
        $(SRC_DIR)/bloom/nexbloom.c \
        $(SRC_DIR)/vector/quantization.c \
        $(SRC_DIR)/vector/router.c \
        $(SRC_DIR)/vector/hnsw.c \
        $(SRC_DIR)/network/protocol_detect.c \
        $(SRC_DIR)/network/websocket.c \
        $(SRC_DIR)/security/quota.c \
        $(SRC_DIR)/util.c \
        $(SRC_DIR)/zmalloc.c

OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
LIB  := $(BUILD_DIR)/libnexcache.a

.PHONY: all clean dirs tests

all: dirs $(LIB) tests

dirs:
	@mkdir -p $(BUILD_DIR)/memory $(BUILD_DIR)/core $(BUILD_DIR)/vector \
	           $(BUILD_DIR)/hashtable $(BUILD_DIR)/segcache $(BUILD_DIR)/crdt \
	           $(BUILD_DIR)/bloom $(BUILD_DIR)/network $(BUILD_DIR)/security

$(LIB): $(OBJS)
	@echo "  [AR]  $@"
	@ar rcs $@ $(OBJS)

$(BUILD_DIR)/vector/quantization.o: $(SRC_DIR)/vector/quantization.c
	@echo "  [CC]  $< (SIMD Optimized)"
	@$(CC) $(CFLAGS) $(SIMD_FLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "  [CC]  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Test Targets
tests: $(BUILD_DIR)/test_arena $(BUILD_DIR)/test_core_v2 $(BUILD_DIR)/test_v4

$(BUILD_DIR)/test_%: $(TEST_DIR)/test_%.c $(LIB)
	@echo "  [LD]  $@"
	@$(CC) $(CFLAGS) $< -o $@ -L$(BUILD_DIR) -lnexcache $(LDFLAGS)

clean:
	@rm -rf $(BUILD_DIR)
