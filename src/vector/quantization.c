#include "quantization.h"
#include <string.h>
#include <math.h>

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#endif

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
static void probe_vector_caps_x86(NexVectorCaps *caps) {
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    caps->avx512f = !!(ebx & (1u << 16));    // AVX-512F
    caps->avx512vnni = !!(ecx & (1u << 11)); // AVX-512 VNNI
    __cpuid_count(7, 1, eax, ebx, ecx, edx);
    caps->avx512bf16 = !!(eax & (1u << 5)); // AVX-512 BF16

    // Not on ARM, defaults to false
    caps->arm_neon = false;
    caps->arm_sve = false;
}
#elif defined(__aarch64__)
#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_ASIMD
#define HWCAP_ASIMD (1 << 1)
#endif
#ifndef HWCAP_SVE
#define HWCAP_SVE (1 << 22)
#endif
static void probe_vector_caps_arm(NexVectorCaps *caps) {
    unsigned long hwcap = getauxval(AT_HWCAP);
    caps->arm_neon = !!(hwcap & HWCAP_ASIMD); // NEON sempre presente su ARM64
    caps->arm_sve = !!(hwcap & HWCAP_SVE);    // SVE opzionale

    // Non x86 capabilities
    caps->avx512f = false;
    caps->avx512vnni = false;
    caps->avx512bf16 = false;
}
#elif defined(__APPLE__)
static void probe_vector_caps_arm(NexVectorCaps *caps) {
    // Apple Silicon has NEON inherently.
    caps->arm_neon = true;
    caps->arm_sve = false;

    caps->avx512f = false;
    caps->avx512vnni = false;
    caps->avx512bf16 = false;
}
#endif
#else
static void probe_vector_caps_unknown(NexVectorCaps *caps) {
    caps->avx512f = false;
    caps->avx512vnni = false;
    caps->avx512bf16 = false;
    caps->arm_neon = false;
    caps->arm_sve = false;
}
#endif

void nexvec_probe_caps(NexVectorCaps *caps) {
    memset(caps, 0, sizeof(NexVectorCaps));
#if defined(__x86_64__) || defined(_M_X64)
    probe_vector_caps_x86(caps);
#elif defined(__aarch64__)
    probe_vector_caps_arm(caps);
#else
    probe_vector_caps_unknown(caps);
#endif
    // GPU availability non rilevata in CPU probe
    caps->gpu_available = false;
    caps->gpu_vram_mb = 0;
}

QuantizationType nexvec_auto_quantization(const NexVectorCaps *caps,
                                          size_t n_vectors,
                                          float recall_threshold) {
    // Se recall_threshold > 0.999: usa FP16 o FP32
    if (recall_threshold > 0.999f) {
        return caps->arm_neon ? QUANT_FP16 : QUANT_FP32;
    }
    // INT8 con AVX-512 VNNI: ottimo trade-off su CPU moderne
    if (caps->avx512vnni && recall_threshold > 0.990f) {
        return QUANT_INT8;
    }
    // ARM NEON: FP16 nativo (AWS Graviton3, Apple M1/M2/M3)
    if (caps->arm_neon && recall_threshold > 0.990f) {
        return QUANT_FP16;
    }
    // Binary: massima compressione, recall non critico
    if (recall_threshold <= 0.950f || n_vectors > 50000000LL) {
        return QUANT_BINARY;
    }
    return QUANT_FP16; // default sicuro
}

#if defined(__x86_64__) || defined(_M_X64)
__attribute__((target("sse4.1,avx2")))
#endif
void
nex_vector_quantize_int8(const float *src, int8_t *dst, size_t dim) {
    /* Mappa [ -1.0, 1.0 ] in [ -127, 127 ] */
    size_t i = 0;
#if defined(__aarch64__)
    float32x4_t scale = vdupq_n_f32(127.0f);
    for (; i + 3 < dim; i += 4) {
        float32x4_t f = vld1q_f32(&src[i]);
        int32x4_t scaled = vcvtq_s32_f32(vmulq_f32(f, scale));
        /* Narrowing s32 -> s16 -> s8 */
        int16x4_t s16 = vmovn_s32(scaled);
        int8x8_t s8 = vmovn_s16(vcombine_s16(s16, s16));
        vst1_lane_s8(&dst[i], s8, 0);
        vst1_lane_s8(&dst[i + 1], s8, 1);
        vst1_lane_s8(&dst[i + 2], s8, 2);
        vst1_lane_s8(&dst[i + 3], s8, 3);
    }
#elif defined(__x86_64__) || defined(_M_X64)
    __m128 vscale = _mm_set1_ps(127.0f);
    for (; i + 3 < dim; i += 4) {
        __m128 f = _mm_loadu_ps(&src[i]);
        __m128i scaled = _mm_cvtps_epi32(_mm_mul_ps(f, vscale));
        /* Pack i32 -> i16 -> i8 */
        __m128i s16 = _mm_packs_epi32(scaled, scaled);
        __m128i s8 = _mm_packs_epi16(s16, s16);
        int32_t res = _mm_cvtsi128_si32(s8);
        memcpy(&dst[i], &res, 4);
    }
#endif
    for (; i < dim; i++) {
        float f = src[i];
        if (f > 1.0f) f = 1.0f;
        if (f < -1.0f) f = -1.0f;
        dst[i] = (int8_t)(f * 127.0f);
    }
}

void nex_vector_quantize_binary(const float *src, uint8_t *dst, size_t dim) {
    size_t num_bytes = (dim + 7) / 8;
    memset(dst, 0, num_bytes);
    for (size_t i = 0; i < dim; i++) {
        if (src[i] > 0) {
            dst[i / 8] |= (1 << (i % 8));
        }
    }
}

#if defined(__x86_64__) || defined(_M_X64)
__attribute__((target("sse4.1,avx2")))
#endif
int32_t
nex_vector_dot_int8(const int8_t *a, const int8_t *b, size_t dim) {
    int32_t sum = 0;
    size_t i = 0;
#if defined(__aarch64__)
    int32x4_t vsum = vdupq_n_s32(0);
    for (; i + 7 < dim; i += 8) {
        int8x8_t va = vld1_s8(&a[i]);
        int8x8_t vb = vld1_s8(&b[i]);
        /* va[i]*vb[i] -> s16 */
        int16x8_t prod = vmull_s8(va, vb);
        vsum = vaddw_s16(vsum, vget_low_s16(prod));
        vsum = vaddw_s16(vsum, vget_high_s16(prod));
    }
    sum = vgetq_lane_s32(vsum, 0) + vgetq_lane_s32(vsum, 1) +
          vgetq_lane_s32(vsum, 2) + vgetq_lane_s32(vsum, 3);
#elif defined(__x86_64__) || defined(_M_X64)
    __m128i vsum = _mm_setzero_si128();
    for (; i + 15 < dim; i += 16) {
        __m128i va = _mm_loadu_si128((__m128i *)&a[i]);
        __m128i vb = _mm_loadu_si128((__m128i *)&b[i]);
        __m128i va_lo = _mm_cvtepi8_epi16(va);
        __m128i vb_lo = _mm_cvtepi8_epi16(vb);
        vsum = _mm_add_epi32(vsum, _mm_madd_epi16(va_lo, vb_lo));
        __m128i va_hi = _mm_cvtepi8_epi16(_mm_srli_si128(va, 8));
        __m128i vb_hi = _mm_cvtepi8_epi16(_mm_srli_si128(vb, 8));
        vsum = _mm_add_epi32(vsum, _mm_madd_epi16(va_hi, vb_hi));
    }
    int32_t tmp[4];
    _mm_storeu_si128((__m128i *)tmp, vsum);
    sum = tmp[0] + tmp[1] + tmp[2] + tmp[3];
#endif
    for (; i < dim; i++) {
        sum += (int32_t)a[i] * b[i];
    }
    return sum;
}

uint32_t nex_vector_hamming_dist(const uint8_t *a, const uint8_t *b, size_t num_bytes) {
    uint32_t dist = 0;
    size_t i = 0;
#if defined(__aarch64__)
    uint64x2_t vsum = vdupq_n_u64(0);
    for (; i + 15 < num_bytes; i += 16) {
        uint8x16_t va = vld1q_u8(&a[i]);
        uint8x16_t vb = vld1q_u8(&b[i]);
        /* XOR -> popcount */
        uint8x16_t vxor = veorq_u8(va, vb);
        uint8x16_t vcnt = vcntq_u8(vxor);
        /* Horizontal sum across lanes */
        uint64x2_t psum = vpaddlq_u32(vpaddlq_u16(vpaddlq_u8(vcnt)));
        vsum = vaddq_u64(vsum, psum);
    }
    dist = (uint32_t)(vgetq_lane_u64(vsum, 0) + vgetq_lane_u64(vsum, 1));
#elif defined(__x86_64__) || defined(_M_X64)
    for (; i + 7 < num_bytes; i += 8) {
        uint64_t vxor = (*(uint64_t *)&a[i]) ^ (*(uint64_t *)&b[i]);
        dist += __builtin_popcountll(vxor);
    }
#endif
    for (; i < num_bytes; i++) {
        uint8_t x = a[i] ^ b[i];
        dist += __builtin_popcount(x);
    }
    return dist;
}
