# NexCache Makefile — v1.0
# ============================================================
CC      ?= gcc
# Usiamo += per permettere a GitHub Actions di aggiungere flag hardware
CFLAGS  += -O3 -std=c11 -Wall -Wextra -pthread -D_GNU_SOURCE \
            -Isrc -Isrc/memory -Isrc/core -Isrc/vector -Isrc/hashtable \
            -Isrc/segcache -Isrc/crdt -Isrc/bloom

UNAME_S := $(shell uname -s)
LDFLAGS += -lpthread -lm
ifneq ($(UNAME_S),Darwin)
    LDFLAGS += -lrt
endif

BUILD_DIR := build
SRC_DIR   := src
TEST_DIR  := tests

# --- TUTTI I MODULI NEXCACHE ---
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
        $(SRC_DIR)/vector/router.c

OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
LIB  := $(BUILD_DIR)/libnexcache.a

all: dirs $(LIB) tests

dirs:
	@mkdir -p $(BUILD_DIR)/memory $(BUILD_DIR)/core $(BUILD_DIR)/vector \
	           $(BUILD_DIR)/hashtable $(BUILD_DIR)/segcache $(BUILD_DIR)/crdt $(BUILD_DIR)/bloom

$(LIB): $(OBJS)
	@echo "  [AR]  $@"
	@ar rcs $@ $(OBJS)

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
