#include "quantization.h"
#include <string.h>

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#endif

/* Dichiarazioni esterne per x86 (isolate in altro file) */
#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
extern void nex_vector_quantize_int8_x86(const float *src, int8_t *dst, size_t dim);
extern int32_t nex_vector_dot_int8_x86(const int8_t *a, const int8_t *b, size_t dim);
#endif

/* --- Rilevamento Hardware --- */
void nexvec_probe_caps(NexVectorCaps *caps) {
    memset(caps, 0, sizeof(NexVectorCaps));
#if defined(__x86_64__) || defined(_M_X64)
    uint32_t eax, ebx, ecx, edx;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    caps->avx512vnni = !!(ecx & (1u << 11));
#elif defined(__aarch64__)
    caps->arm_neon = true;
#endif
}

void nex_vector_quantize_int8(const float *src, int8_t *dst, size_t dim) {
#if defined(__aarch64__)
    size_t i = 0;
    float32x4_t scale = vdupq_n_f32(127.0f);
    for (; i + 3 < dim; i += 4) {
        float32x4_t f = vld1q_f32(&src[i]);
        int32x4_t scaled = vcvtq_s32_f32(vmulq_f32(f, scale));
        int16x4_t s16 = vmovn_s32(scaled);
        int8x8_t s8 = vmovn_s16(vcombine_s16(s16, s16));
        vst1_lane_s8(&dst[i], s8, 0);
        vst1_lane_s8(&dst[i + 1], s8, 1);
        vst1_lane_s8(&dst[i + 2], s8, 2);
        vst1_lane_s8(&dst[i + 3], s8, 3);
    }
    for (; i < dim; i++) {
        float f = src[i];
        if (f > 1.0f)
            f = 1.0f;
        else if (f < -1.0f)
            f = -1.0f;
        dst[i] = (int8_t)(f * 127.0f);
    }
#elif defined(__x86_64__) || defined(_M_X64)
    nex_vector_quantize_int8_x86(src, dst, dim);
#else
    for (size_t i = 0; i < dim; i++) {
        float f = src[i];
        if (f > 1.0f)
            f = 1.0f;
        else if (f < -1.0f)
            f = -1.0f;
        dst[i] = (int8_t)(f * 127.0f);
    }
#endif
}

int32_t nex_vector_dot_int8(const int8_t *a, const int8_t *b, size_t dim) {
#if defined(__aarch64__)
    int32x4_t vsum = vdupq_n_s32(0);
    size_t i = 0;
    for (; i + 7 < dim; i += 8) {
        int8x8_t va = vld1_s8(&a[i]);
        int8x8_t vb = vld1_s8(&b[i]);
        int16x8_t prod = vmull_s8(va, vb);
        vsum = vaddw_s16(vsum, vget_low_s16(prod));
        vsum = vaddw_s16(vsum, vget_high_s16(prod));
    }
    int32_t sum = vgetq_lane_s32(vsum, 0) + vgetq_lane_s32(vsum, 1) + vgetq_lane_s32(vsum, 2) + vgetq_lane_s32(vsum, 3);
    for (; i < dim; i++) sum += (int32_t)a[i] * b[i];
    return sum;
#elif defined(__x86_64__) || defined(_M_X64)
    return nex_vector_dot_int8_x86(a, b, dim);
#else
    int32_t sum = 0;
    for (size_t i = 0; i < dim; i++) sum += (int32_t)a[i] * b[i];
    return sum;
#endif
}

uint32_t nex_vector_hamming_dist(const uint8_t *a, const uint8_t *b, size_t num_bytes) {
    uint32_t dist = 0;
    for (size_t i = 0; i < num_bytes; i++) dist += __builtin_popcount(a[i] ^ b[i]);
    return dist;
}
