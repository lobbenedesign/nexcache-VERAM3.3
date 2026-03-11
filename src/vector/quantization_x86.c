#include "quantization.h"

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include <string.h>

/* Funzioni Kernel Intel (compilate con -mavx2 -msse4.1) */
void nex_vector_quantize_int8_x86(const float *src, int8_t *dst, size_t dim) {
    size_t i = 0;
    __m128 vscale = _mm_set1_ps(127.0f);
    for (; i + 3 < dim; i += 4) {
        __m128 f = _mm_loadu_ps(&src[i]);
        __m128i scaled = _mm_cvtps_epi32(_mm_mul_ps(f, vscale));
        __m128i s16 = _mm_packs_epi32(scaled, scaled);
        __m128i s8 = _mm_packs_epi16(s16, s16);
        int32_t res = _mm_cvtsi128_si32(s8);
        memcpy(&dst[i], &res, 4);
    }
    for (; i < dim; i++) {
        float f = src[i];
        if (f > 1.0f)
            f = 1.0f;
        else if (f < -1.0f)
            f = -1.0f;
        dst[i] = (int8_t)(f * 127.0f);
    }
}

int32_t nex_vector_dot_int8_x86(const int8_t *a, const int8_t *b, size_t dim) {
    int32_t sum = 0;
    size_t i = 0;
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
    for (; i < dim; i++) sum += (int32_t)a[i] * b[i];
    return sum;
}
#endif
