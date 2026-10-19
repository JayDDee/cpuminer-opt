#pragma once
// exp256 (fixed exponent, mod 2^256-189) for many values at once with
// AVX-512 IFMA: 8 values per zmm, 5x52-bit limbs, the same square/multiply
// schedule as FixedExponent::operator(). The exponent is a constant, so all
// lanes run identical code. The scalar FixedExponent stays the oracle: the
// startup lanes self-test compares this path against it.
#if defined(__x86_64__) && defined(__AVX512F__) && defined(__AVX512IFMA__) && !defined(BC3HASH_NO_IFMA)
#define BC3_IFMA_EXP 1
#include "bc3hash-uint.hpp"
#include <immintrin.h>

namespace bc3 {
namespace detail {
namespace ifma {
constexpr std::uint64_t M52 = (std::uint64_t(1) << 52) - 1;
// 2^260 = 16 * 2^256 = 16 * 189 (mod 2^256-189).
constexpr std::uint64_t R = 16 * 189;
// 8 values; each limb < 2^52 (IFMA reads only the low 52 bits of its
// operands), value < 2^260 and congruent, not canonical.
struct F {
    __m512i l[5];
};
__attribute__((always_inline)) inline F mul(const F& a, const F& b)
{
    const __m512i z = _mm512_setzero_si512(), m = _mm512_set1_epi64(M52), r = _mm512_set1_epi64(R);
    __m512i c[10];
    for (unsigned k = 0; k < 10; ++k)
        c[k] = z;
    // Column sums: each gets at most 5 low and 5 high halves, < 2^56.
    for (unsigned i = 0; i < 5; ++i)
        for (unsigned j = 0; j < 5; ++j) {
            c[i + j] = _mm512_madd52lo_epu64(c[i + j], a.l[i], b.l[j]);
            c[i + j + 1] = _mm512_madd52hi_epu64(c[i + j + 1], a.l[i], b.l[j]);
        }
    // To 52-bit limbs. The product is < 2^520, so nothing carries out of 9.
    __m512i carry = z;
    for (unsigned k = 0; k < 10; ++k) {
        const __m512i t = _mm512_add_epi64(c[k], carry);
        c[k] = _mm512_and_si512(t, m);
        carry = _mm512_srli_epi64(t, 52);
    }
    // Fold limbs 5..9 (weight 2^260 * 2^52i == R * 2^52i): low half of
    // h_i*R at limb i, high half at limb i+1, h_4's high half back to 0.
    F o;
    for (unsigned i = 0; i < 5; ++i)
        o.l[i] = _mm512_madd52lo_epu64(c[i], c[i + 5], r);
    for (unsigned i = 0; i < 4; ++i)
        o.l[i + 1] = _mm512_madd52hi_epu64(o.l[i + 1], c[i + 5], r);
    const __m512i top = _mm512_madd52hi_epu64(z, c[9], r);
    o.l[0] = _mm512_madd52lo_epu64(o.l[0], top, r);
    // Limbs now < 2^54. Two ripples: the first's carry out (weight 2^260,
    // < 8) folds back into limb 0; if the second carries out again, the
    // value was just above 2^260, so the rest is < 2^15 and + R cannot
    // reach 2^52.
    for (unsigned pass = 0; pass < 2; ++pass) {
        carry = z;
        for (unsigned i = 0; i < 5; ++i) {
            const __m512i t = _mm512_add_epi64(o.l[i], carry);
            o.l[i] = _mm512_and_si512(t, m);
            carry = _mm512_srli_epi64(t, 52);
        }
        o.l[0] = _mm512_madd52lo_epu64(o.l[0], carry, r);
    }
    return o;
}
// lanes[0..7] (canonical, < p) into one F.
inline F load(const U256* v)
{
    alignas(64) std::uint64_t t[5][8];
    for (unsigned k = 0; k < 8; ++k) {
        const auto& x = v[k].v;
        t[0][k] = x[0] & M52;
        t[1][k] = ((x[0] >> 52) | (x[1] << 12)) & M52;
        t[2][k] = ((x[1] >> 40) | (x[2] << 24)) & M52;
        t[3][k] = ((x[2] >> 28) | (x[3] << 36)) & M52;
        t[4][k] = x[3] >> 16;
    }
    F f;
    for (unsigned i = 0; i < 5; ++i)
        f.l[i] = _mm512_load_si512(t[i]);
    return f;
}
// Back to canonical 4x64 in [0, p): repack, fold the 4 bits above 2^256
// (x 189), and let M256::reduce finish exactly as the scalar path does.
inline void store(const F& f, U256* v)
{
    alignas(64) std::uint64_t t[5][8];
    for (unsigned i = 0; i < 5; ++i)
        _mm512_store_si512(t[i], f.l[i]);
    for (unsigned k = 0; k < 8; ++k) {
        std::array<std::uint64_t, 8> w{};
        w[0] = t[0][k] | (t[1][k] << 52);
        w[1] = (t[1][k] >> 12) | (t[2][k] << 40);
        w[2] = (t[2][k] >> 24) | (t[3][k] << 28);
        w[3] = (t[3][k] >> 36) | (t[4][k] << 16);
        w[4] = t[4][k] >> 48;
        v[k] = M256::reduce(w);
    }
}
// out[i] = in[i]^E for 8*G values, E being e's exponent.
template <unsigned G>
void exp_groups(const FixedExponent<M256, 4>& e, const U256* in, U256* out)
{
    F odd[G][8], a2[G], r[G];
    for (unsigned g = 0; g < G; ++g) {
        U256 n[8];
        for (unsigned k = 0; k < 8; ++k)
            n[k] = M256::normalize(in[8 * g + k]);
        odd[g][0] = load(n);
    }
    for (unsigned g = 0; g < G; ++g)
        a2[g] = mul(odd[g][0], odd[g][0]);
    for (unsigned i = 1; i < 8; ++i)
        for (unsigned g = 0; g < G; ++g)
            odd[g][i] = mul(odd[g][i - 1], a2[g]);
    for (unsigned g = 0; g < G; ++g)
        r[g] = odd[g][e.steps[0].index];
    for (unsigned s = 1; s < e.count; ++s) {
        for (unsigned q = 0; q < e.steps[s].squares; ++q)
            for (unsigned g = 0; g < G; ++g)
                r[g] = mul(r[g], r[g]);
        for (unsigned g = 0; g < G; ++g)
            r[g] = mul(r[g], odd[g][e.steps[s].index]);
    }
    for (unsigned q = 0; q < e.tail; ++q)
        for (unsigned g = 0; g < G; ++g)
            r[g] = mul(r[g], r[g]);
    for (unsigned g = 0; g < G; ++g)
        store(r[g], out + 8 * g);
}
} // namespace ifma
} // namespace detail
} // namespace bc3
#endif
