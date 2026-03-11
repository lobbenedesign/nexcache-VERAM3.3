CC      ?= gcc
CFLAGS  := -O2 -std=c11 -Wall -Wextra -Wpedantic -pthread -D_GNU_SOURCE \
            -Isrc -Isrc/memory -Isrc/core -Isrc/vector -Isrc/hashtable -Isrc/segcache

UNAME_S := $(shell uname -s)
ARCH    := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    LDFLAGS := -lpthread -lm
else
    LDFLAGS := -lpthread -lm -lrt
endif

BUILD_DIR := build
SRC_DIR   := src
TEST_DIR  := tests

# Sorgenti
SRCS := $(SRC_DIR)/memory/arena.c $(SRC_DIR)/memory/hybrid.c \
        $(SRC_DIR)/core/engine.c $(SRC_DIR)/core/scheduler.c \
        $(SRC_DIR)/hashtable/nexdash.c $(SRC_DIR)/segcache/segcache.c \
        $(SRC_DIR)/vector/quantization.c

# Aggiungi file x86 se siamo su x86
ifeq ($(ARCH),x86_64)
    SRCS += $(SRC_DIR)/vector/quantization_x86.c
endif

OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
LIB  := $(BUILD_DIR)/libnexcache.a

all: dirs $(LIB) tests

dirs:
	@mkdir -p $(BUILD_DIR)/memory $(BUILD_DIR)/core $(BUILD_DIR)/vector $(BUILD_DIR)/hashtable $(BUILD_DIR)/segcache

$(LIB): $(OBJS)
	@ar rcs $@ $^

# --- Regola Chirurgica per x86 SIMD ---
$(BUILD_DIR)/vector/quantization_x86.o: $(SRC_DIR)/vector/quantization_x86.c
	@echo "  [CC]  $< (Intel SIMD Optimized)"
	@$(CC) $(CFLAGS) -msse4.1 -mavx2 -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "  [CC]  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

tests: $(BUILD_DIR)/test_arena $(BUILD_DIR)/test_v4

$(BUILD_DIR)/test_%: $(TEST_DIR)/test_%.c $(LIB)
	@$(CC) $(CFLAGS) $< -o $@ -L$(BUILD_DIR) -lnexcache $(LDFLAGS)

clean:
	@rm -rf $(BUILD_DIR)
