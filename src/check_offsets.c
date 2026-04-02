#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>

#define LRULFU_BITS 24
#define OBJ_REFCOUNT_BITS 29

struct serverObject {
    unsigned type : 4;
    unsigned encoding : 4;
    unsigned lru : LRULFU_BITS;
    unsigned hasexpire : 1;
    unsigned hasembkey : 1;
    unsigned hasembval : 1;
    unsigned refcount : OBJ_REFCOUNT_BITS;
    void *val_ptr;
    char svi_payload[240];
};

int main() {
    printf("sizeof(robj): %zu\n", sizeof(struct serverObject));
    printf("offset of val_ptr: %zu\n", offsetof(struct serverObject, val_ptr));
    printf("offset of svi_payload: %zu\n", offsetof(struct serverObject, svi_payload));
    return 0;
}
