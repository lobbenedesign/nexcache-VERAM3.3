/* Forziamo l'architettura Intel PRIA di ogni inclusione per GitHub Actions */
#if defined(__x86_64__) || defined(_M_X64)
#pragma GCC push_options
#pragma GCC target("sse4.1,avx2")
#endif

#include "quantization.h"
#include <string.h>

#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#endif

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include <cpuid.h>
#endif

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
    size_t i = 0;
#if defined(__aarch64__)
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
#elif defined(__x86_64__) || defined(_M_X64)
    __m128 vscale = _mm_set1_ps(127.0f);
    for (; i + 3 < dim; i += 4) {
        __m128 f = _mm_loadu_ps(&src[i]);
        __m128i scaled = _mm_cvtps_epi32(_mm_mul_ps(f, vscale));
        __m128i s16 = _mm_packs_epi32(scaled, scaled);
        __m128i s8 = _mm_packs_epi16(s16, s16);
        int32_t res = _mm_cvtsi128_si32(s8);
        memcpy(&dst[i], &res, 4);
    }
#endif
    for (; i < dim; i++) {
        float f = src[i];
        if (f > 1.0f)
            f = 1.0f;
        else if (f < -1.0f)
            f = -1.0f;
        dst[i] = (int8_t)(f * 127.0f);
    }
}

int32_t nex_vector_dot_int8(const int8_t *a, const int8_t *b, size_t dim) {
    int32_t sum = 0;
    size_t i = 0;
#if defined(__aarch64__)
    int32x4_t vsum = vdupq_n_s32(0);
    for (; i + 7 < dim; i += 8) {
        int8x8_t va = vld1_s8(&a[i]);
        int8x8_t vb = vld1_s8(&b[i]);
        vsum = vaddw_s16(vsum, vget_low_s16(vmull_s8(va, vb)));
        vsum = vaddw_s16(vsum, vget_high_s16(vmull_s8(va, vb)));
    }
    sum = vgetq_lane_s32(vsum, 0) + vgetq_lane_s32(vsum, 1) + vgetq_lane_s32(vsum, 2) + vgetq_lane_s32(vsum, 3);
#elif defined(__x86_64__) || defined(_M_X64)
    __m128i vsum = _mm_setzero_si128();
    for (; i + 15 < dim; i += 16) {
        __m128i va = _mm_loadu_si128((__m128i *)&a[i]);
        __m128i vb = _mm_loadu_si128((__m128i *)&b[i]);
        vsum = _mm_add_epi32(vsum, _mm_madd_epi16(_mm_cvtepi8_epi16(va), _mm_cvtepi8_epi16(vb)));
        vsum = _mm_add_epi32(vsum, _mm_madd_epi16(_mm_cvtepi8_epi16(_mm_srli_si128(va, 8)), _mm_cvtepi8_epi16(_mm_srli_si128(vb, 8))));
    }
    int32_t tmp[4];
    _mm_storeu_si128((__m128i *)tmp, vsum);
    sum = tmp[0] + tmp[1] + tmp[2] + tmp[3];
#endif
    for (; i < dim; i++) sum += (int32_t)a[i] * b[i];
    return sum;
}

uint32_t nex_vector_hamming_dist(const uint8_t *a, const uint8_t *b, size_t num_bytes) {
    uint32_t dist = 0;
    for (size_t i = 0; i < num_bytes; i++) dist += __builtin_popcount(a[i] ^ b[i]);
    return dist;
}

#if defined(__x86_64__) || defined(_M_X64)
#pragma GCC pop_options
#endif
