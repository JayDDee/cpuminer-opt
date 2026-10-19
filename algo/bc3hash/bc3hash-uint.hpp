#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#if defined(__x86_64__) && defined(__BMI2__) && defined(__ADX__)
#include <immintrin.h>
#endif

namespace bc3 {
namespace detail {
// 128-bit layer: the compiler's __int128, so a 64-bit target is required
// (the coin's own backend has the same requirement).
using Wide = unsigned __int128;
using SignedWide = __int128;
template <std::size_t L>
struct UInt {
    std::array<std::uint64_t, L> v{}; // least significant limb first
    UInt() = default;
    UInt(std::uint64_t x) { v[0] = x; }
    template <std::size_t M>
    explicit UInt(const UInt<M>& x)
    {
        for (std::size_t i = 0; i < L && i < M; ++i)
            v[i] = x.v[i];
    }
    static UInt hex(const char* s)
    {
        UInt r;
        for (; *s; ++s) {
            unsigned d = *s >= '0' && *s <= '9' ? unsigned(*s - '0') : unsigned(*s - 'a' + 10);
            for (std::size_t i = L - 1; i > 0; --i)
                r.v[i] = (r.v[i] << 4) | (r.v[i - 1] >> 60);
            r.v[0] = (r.v[0] << 4) | d;
        }
        return r;
    }
    static UInt load(const void* p)
    {
        const auto* b = static_cast<const std::uint8_t*>(p);
        UInt r;
        for (std::size_t i = 0; i < L; ++i)
            for (unsigned j = 0; j < 8; ++j)
                r.v[L - 1 - i] = (r.v[L - 1 - i] << 8) | b[i * 8 + j];
        return r;
    }
    void store(void* p) const
    {
        auto* b = static_cast<std::uint8_t*>(p);
        for (std::size_t i = 0; i < L; ++i)
            for (unsigned j = 0; j < 8; ++j)
                b[i * 8 + j] = std::uint8_t(v[L - 1 - i] >> (56 - j * 8));
    }
    bool zero() const
    {
        std::uint64_t r = 0;
        for (auto x : v)
            r |= x;
        return r == 0;
    }
    unsigned byte(std::size_t i) const { return unsigned((v[i / 8] >> (8 * (i % 8))) & 255); }
    friend bool operator==(const UInt& a, const UInt& b) { return a.v == b.v; }
    friend bool operator!=(const UInt& a, const UInt& b) { return !(a == b); }
    friend bool operator<(const UInt& a, const UInt& b)
    {
        for (std::size_t i = L; i--;) {
            if (a.v[i] != b.v[i]) return a.v[i] < b.v[i];
        }
        return false;
    }
    friend bool operator>=(const UInt& a, const UInt& b) { return !(a < b); }
    friend UInt operator+(const UInt& a, const UInt& b)
    {
        UInt r;
        Wide c = 0;
        for (std::size_t i = 0; i < L; ++i) {
            c = Wide(a.v[i]) + b.v[i] + std::uint64_t(c >> 64);
            r.v[i] = std::uint64_t(c);
        }
        return r;
    }
    friend UInt operator-(const UInt& a, const UInt& b)
    {
        UInt r;
        std::uint64_t borrow = 0;
        for (std::size_t i = 0; i < L; ++i) {
            Wide t = Wide(b.v[i]) + borrow;
            r.v[i] = a.v[i] - std::uint64_t(t);
            borrow = Wide(a.v[i]) < t;
        }
        return r;
    }
    friend UInt operator^(const UInt& a, const UInt& b)
    {
        UInt r;
        for (std::size_t i = 0; i < L; ++i)
            r.v[i] = a.v[i] ^ b.v[i];
        return r;
    }
    friend UInt operator&(const UInt& a, const UInt& b)
    {
        UInt r;
        for (std::size_t i = 0; i < L; ++i)
            r.v[i] = a.v[i] & b.v[i];
        return r;
    }
    friend UInt operator|(const UInt& a, const UInt& b)
    {
        UInt r;
        for (std::size_t i = 0; i < L; ++i)
            r.v[i] = a.v[i] | b.v[i];
        return r;
    }
    friend UInt operator~(const UInt& a)
    {
        UInt r;
        for (std::size_t i = 0; i < L; ++i)
            r.v[i] = ~a.v[i];
        return r;
    }
};
using U64 = UInt<1>;
using U128 = UInt<2>;
using U256 = UInt<4>;

// Limb shifts and rotations as straight-line code: as loops, gcc vectorizes
// the (i + K) % L limb index into slow gathers on AVX2/AVX-512 targets.
template <unsigned N, std::size_t L>
inline std::uint64_t shr_limb(const UInt<L>& a, std::size_t i)
{
    std::uint64_t r = i + N / 64 < L ? a.v[i + N / 64] >> (N % 64) : 0;
    if (N % 64 && i + N / 64 + 1 < L) r |= a.v[i + N / 64 + 1] << ((64 - N % 64) % 64);
    return r;
}
template <unsigned N, std::size_t L, std::size_t... I>
inline UInt<L> shr_impl(const UInt<L>& a, std::index_sequence<I...>)
{
    UInt<L> r;
    ((r.v[I] = shr_limb<N, L>(a, I)), ...);
    return r;
}
template <unsigned N, std::size_t L>
inline UInt<L> shr(const UInt<L>& a)
{
    return shr_impl<N, L>(a, std::make_index_sequence<L>{});
}
template <unsigned N, std::size_t L, std::size_t I>
inline std::uint64_t ror_limb(const UInt<L>& a)
{
    std::uint64_t r = a.v[(I + N / 64) % L] >> (N % 64);
    if (N % 64) r |= a.v[(I + N / 64 + 1) % L] << ((64 - N % 64) % 64);
    return r;
}
template <unsigned N, std::size_t L, std::size_t... I>
inline UInt<L> ror_impl(const UInt<L>& a, std::index_sequence<I...>)
{
    UInt<L> r;
    ((r.v[I] = ror_limb<N, L, I>(a)), ...);
    return r;
}
template <unsigned N, std::size_t L>
inline UInt<L> ror(const UInt<L>& a)
{
    return ror_impl<N, L>(a, std::make_index_sequence<L>{});
}
template <unsigned N, std::size_t L>
inline UInt<L> rol(const UInt<L>& a)
{
    return ror<unsigned(L * 64) - N % (L * 64)>(a);
}
template <std::size_t L>
inline UInt<L> ch(const UInt<L>& x, const UInt<L>& y, const UInt<L>& z)
{
    return z ^ (x & (y ^ z));
}
template <std::size_t L>
inline UInt<L> maj(const UInt<L>& x, const UInt<L>& y, const UInt<L>& z)
{
    return (x & y) | (z & (x | y));
}
template <std::size_t L>
inline UInt<L> Sig0(const UInt<L>& x)
{
    if (L == 1) return ror<28>(x) ^ ror<34>(x) ^ ror<39>(x);
    if (L == 2) return ror<57>(x) ^ ror<63>(x) ^ ror<92>(x);
    if (L == 4) return ror<113>(x) ^ ror<146>(x) ^ ror<171>(x);
}
template <std::size_t L>
inline UInt<L> Sig1(const UInt<L>& x)
{
    if (L == 1) return ror<14>(x) ^ ror<18>(x) ^ ror<41>(x);
    if (L == 2) return ror<35>(x) ^ ror<44>(x) ^ ror<51>(x);
    if (L == 4) return ror<88>(x) ^ ror<97>(x) ^ ror<201>(x);
}
template <std::size_t L>
inline UInt<L> sig0(const UInt<L>& x)
{
    if (L == 1) return ror<1>(x) ^ ror<8>(x) ^ shr<7>(x);
    if (L == 2) return ror<42>(x) ^ ror<83>(x) ^ shr<20>(x);
    if (L == 4) return ror<131>(x) ^ ror<57>(x) ^ shr<56>(x);
}
template <std::size_t L>
inline UInt<L> sig1(const UInt<L>& x)
{
    if (L == 1) return ror<19>(x) ^ ror<61>(x) ^ shr<6>(x);
    if (L == 2) return ror<24>(x) ^ ror<119>(x) ^ shr<18>(x);
    if (L == 4) return ror<53>(x) ^ ror<247>(x) ^ shr<26>(x);
}
template <std::size_t L>
inline UInt<L> beta(const UInt<L>& x)
{
    constexpr unsigned rotation{L == 1 ? 51 : L == 2 ? 54 :
                                                       81};
    return x ^ Sig0(x) ^ Sig1(x) ^ sig0(x) ^ sig1(x) ^ rol<rotation>(x);
}
template <std::size_t L>
inline UInt<L> gamma(const UInt<L>& x, const UInt<L>& y)
{
    constexpr unsigned right_rotation{L == 1 ? 30 : L == 2 ? 48 :
                                                             58};
    constexpr unsigned left_rotation{L == 1 ? 38 : L == 2 ? 99 :
                                                            183};
    constexpr unsigned shift{L == 1 ? 12 : L == 2 ? 22 :
                                                    32};
    return x ^ beta(y) ^ ror<right_rotation>(y) ^ rol<left_rotation>(sig1(x)) ^ shr<shift>(y);
}
// x86-64 BMI2+ADX: 4-limb product and 2^256-C reduction with mulx and
// explicit carry chains; gcc spills the portable __int128 forms.
#if defined(__x86_64__) && defined(__BMI2__) && defined(__ADX__)
#define BC3_MULX4 1
using ull = unsigned long long;
// t[0..4] (+)= ai * b, t[4] written fresh.
__attribute__((always_inline)) inline void mulx_row(std::uint64_t ai, const std::array<std::uint64_t, 4>& b, std::uint64_t* t, bool first)
{
    ull h0, h1, h2, h3;
    ull l0 = _mulx_u64(ai, b[0], &h0);
    ull l1 = _mulx_u64(ai, b[1], &h1);
    ull l2 = _mulx_u64(ai, b[2], &h2);
    ull l3 = _mulx_u64(ai, b[3], &h3);
    unsigned char c = _addcarry_u64(0, l1, h0, &l1);
    c = _addcarry_u64(c, l2, h1, &l2);
    c = _addcarry_u64(c, l3, h2, &l3);
    h3 += c;
    if (first) {
        t[0] = l0; t[1] = l1; t[2] = l2; t[3] = l3; t[4] = h3;
        return;
    }
    ull r0, r1, r2, r3;
    c = _addcarry_u64(0, t[0], l0, &r0);
    c = _addcarry_u64(c, t[1], l1, &r1);
    c = _addcarry_u64(c, t[2], l2, &r2);
    c = _addcarry_u64(c, t[3], l3, &r3);
    t[0] = r0; t[1] = r1; t[2] = r2; t[3] = r3; t[4] = h3 + c;
}
__attribute__((always_inline)) inline std::array<std::uint64_t, 8> mulx4(const std::array<std::uint64_t, 4>& a, const std::array<std::uint64_t, 4>& b)
{
    std::array<std::uint64_t, 8> t;
    mulx_row(a[0], b, &t[0], true);
    mulx_row(a[1], b, &t[1], false);
    mulx_row(a[2], b, &t[2], false);
    mulx_row(a[3], b, &t[3], false);
    return t;
}
template <std::uint64_t C>
__attribute__((always_inline)) inline std::array<std::uint64_t, 4> reducex4(const std::array<std::uint64_t, 8>& t)
{
    ull q0, q1, q2, q3, r0, r1, r2, r3;
    ull p0 = _mulx_u64(t[4], C, &q0);
    ull p1 = _mulx_u64(t[5], C, &q1);
    ull p2 = _mulx_u64(t[6], C, &q2);
    ull p3 = _mulx_u64(t[7], C, &q3);
    unsigned char c = _addcarry_u64(0, p1, q0, &p1);
    c = _addcarry_u64(c, p2, q1, &p2);
    c = _addcarry_u64(c, p3, q2, &p3);
    q3 += c;
    c = _addcarry_u64(0, t[0], p0, &r0);
    c = _addcarry_u64(c, t[1], p1, &r1);
    c = _addcarry_u64(c, t[2], p2, &r2);
    c = _addcarry_u64(c, t[3], p3, &r3);
    const ull top = q3 + c; // <= C
    c = _addcarry_u64(0, r0, top * C, &r0);
    c = _addcarry_u64(c, r1, 0, &r1);
    c = _addcarry_u64(c, r2, 0, &r2);
    c = _addcarry_u64(c, r3, 0, &r3);
    if (c) r0 += C; // r is tiny here, so this cannot carry
    // normalize: r >= 2^256 - C only if the top three limbs are all ones
    if ((r1 & r2 & r3) == ~0ULL && r0 >= 0 - C) r0 += C, r1 = r2 = r3 = 0;
    return {r0, r1, r2, r3};
}
// Needs 13 free GPRs: unoptimized builds (frame pointer, operand copies)
// cannot satisfy the constraints, so they keep the intrinsic version.
#if !defined(BC3HASH_NO_ASM_MUL) && defined(__OPTIMIZE__)
#define BC3_ASM_MUL4 1
// a*b mod 2^256-C in one asm block, canonical result, all in registers (the
// intrinsic version above spills). mulx rows on two carry chains (adox: low
// halves, adcx: high halves) with rotating accumulators, two folds of the
// high half, then one branch-free subtract of p.
template <std::uint64_t C>
__attribute__((always_inline)) inline std::array<std::uint64_t, 4> mulmod_asm(const std::uint64_t* a, const std::uint64_t* b)
{
    static_assert(C < (1u << 31), "C must fit a sign-extended imm32");
    std::uint64_t r0, r1, r2, r3, r4, s0, s1, s2, lo, hi;
    __asm__(
        // row 0: t0..t4 = a0*b
        "movq   (%[a]), %%rdx\n\t"
        "mulx   (%[b]), %[r0], %[r1]\n\t"
        "mulx  8(%[b]), %[lo], %[r2]\n\t"
        "addq   %[lo], %[r1]\n\t"
        "mulx 16(%[b]), %[lo], %[r3]\n\t"
        "adcq   %[lo], %[r2]\n\t"
        "mulx 24(%[b]), %[lo], %[r4]\n\t"
        "adcq   %[lo], %[r3]\n\t"
        "adcq   $0, %[r4]\n\t"
        "movq   %[r0], %[s0]\n\t"
        // row 1: t1..t4 += a1*b, t5 -> r0
        "movq  8(%[a]), %%rdx\n\t"
        "xorl   %k[lo], %k[lo]\n\t"
        "mulx   (%[b]), %[lo], %[hi]\n\t"
        "adox   %[lo], %[r1]\n\t"
        "adcx   %[hi], %[r2]\n\t"
        "mulx  8(%[b]), %[lo], %[hi]\n\t"
        "adox   %[lo], %[r2]\n\t"
        "adcx   %[hi], %[r3]\n\t"
        "mulx 16(%[b]), %[lo], %[hi]\n\t"
        "adox   %[lo], %[r3]\n\t"
        "adcx   %[hi], %[r4]\n\t"
        "mulx 24(%[b]), %[lo], %[r0]\n\t"
        "adox   %[lo], %[r4]\n\t"
        "movl   $0, %k[lo]\n\t"
        "adcx   %[lo], %[r0]\n\t"
        "adox   %[lo], %[r0]\n\t"
        "movq   %[r1], %[s1]\n\t"
        // row 2: t2..t5 += a2*b, t6 -> r1
        "movq 16(%[a]), %%rdx\n\t"
        "xorl   %k[lo], %k[lo]\n\t"
        "mulx   (%[b]), %[lo], %[hi]\n\t"
        "adox   %[lo], %[r2]\n\t"
        "adcx   %[hi], %[r3]\n\t"
        "mulx  8(%[b]), %[lo], %[hi]\n\t"
        "adox   %[lo], %[r3]\n\t"
        "adcx   %[hi], %[r4]\n\t"
        "mulx 16(%[b]), %[lo], %[hi]\n\t"
        "adox   %[lo], %[r4]\n\t"
        "adcx   %[hi], %[r0]\n\t"
        "mulx 24(%[b]), %[lo], %[r1]\n\t"
        "adox   %[lo], %[r0]\n\t"
        "movl   $0, %k[lo]\n\t"
        "adcx   %[lo], %[r1]\n\t"
        "adox   %[lo], %[r1]\n\t"
        "movq   %[r2], %[s2]\n\t"
        // row 3: t3..t6 += a3*b, t7 -> r2. Now t0..t3 = s0 s1 s2 r3, t4..t7 = r4 r0 r1 r2
        "movq 24(%[a]), %%rdx\n\t"
        "xorl   %k[lo], %k[lo]\n\t"
        "mulx   (%[b]), %[lo], %[hi]\n\t"
        "adox   %[lo], %[r3]\n\t"
        "adcx   %[hi], %[r4]\n\t"
        "mulx  8(%[b]), %[lo], %[hi]\n\t"
        "adox   %[lo], %[r4]\n\t"
        "adcx   %[hi], %[r0]\n\t"
        "mulx 16(%[b]), %[lo], %[hi]\n\t"
        "adox   %[lo], %[r0]\n\t"
        "adcx   %[hi], %[r1]\n\t"
        "mulx 24(%[b]), %[lo], %[r2]\n\t"
        "adox   %[lo], %[r1]\n\t"
        "movl   $0, %k[lo]\n\t"
        "adcx   %[lo], %[r2]\n\t"
        "adox   %[lo], %[r2]\n\t"
        // fold: (s0 s1 s2 r3) += C*(r4 r0 r1 r2); the top word lands in r4, <= C+1
        "movq   %[c], %%rdx\n\t"
        "xorl   %k[lo], %k[lo]\n\t"
        "mulx   %[r4], %[lo], %[hi]\n\t"
        "adox   %[lo], %[s0]\n\t"
        "adcx   %[hi], %[s1]\n\t"
        "mulx   %[r0], %[lo], %[hi]\n\t"
        "adox   %[lo], %[s1]\n\t"
        "adcx   %[hi], %[s2]\n\t"
        "mulx   %[r1], %[lo], %[hi]\n\t"
        "adox   %[lo], %[s2]\n\t"
        "adcx   %[hi], %[r3]\n\t"
        "mulx   %[r2], %[lo], %[r4]\n\t"
        "adox   %[lo], %[r3]\n\t"
        "movl   $0, %k[lo]\n\t"
        "adcx   %[lo], %[r4]\n\t"
        "adox   %[lo], %[r4]\n\t"
        // second fold: top*C < 2^35; a carry out leaves r < 2^35, so + C cannot carry
        "imulq  %[c], %[r4], %[r4]\n\t"
        "addq   %[r4], %[s0]\n\t"
        "adcq   $0, %[s1]\n\t"
        "adcq   $0, %[s2]\n\t"
        "adcq   $0, %[r3]\n\t"
        "sbbq   %[lo], %[lo]\n\t"
        "andq   %[c], %[lo]\n\t"
        "addq   %[lo], %[s0]\n\t"
        // canonical: if r + C carries, r >= p, so r - p = r + C mod 2^256
        "movq   %[s0], %[r0]\n\t"
        "addq   %[c], %[r0]\n\t"
        "movq   %[s1], %[r1]\n\t"
        "adcq   $0, %[r1]\n\t"
        "movq   %[s2], %[r2]\n\t"
        "adcq   $0, %[r2]\n\t"
        "movq   %[r3], %[r4]\n\t"
        "adcq   $0, %[r4]\n\t"
        "cmovcq %[r0], %[s0]\n\t"
        "cmovcq %[r1], %[s1]\n\t"
        "cmovcq %[r2], %[s2]\n\t"
        "cmovcq %[r4], %[r3]\n\t"
        : [r0] "=&r"(r0), [r1] "=&r"(r1), [r2] "=&r"(r2), [r3] "=&r"(r3), [r4] "=&r"(r4),
          [s0] "=&r"(s0), [s1] "=&r"(s1), [s2] "=&r"(s2), [lo] "=&r"(lo), [hi] "=&r"(hi)
        : [a] "r"(a), [b] "r"(b), [c] "i"(C)
        // "memory", not "m" operands for a[] and b[]: clang gives each "m"
        // its own address register, and 13 + 2 GPRs can fail to allocate.
        : "rdx", "cc", "memory");
    (void)r0; (void)r1; (void)r2; (void)r4; (void)hi;
    return {s0, s1, s2, r3};
}
#endif
#endif
// All algorithm moduli have the form 2^(64*L)-C, with small C.
// Two carry folds suffice: the first carry is <= C, the next <= 1.
template <std::size_t L, std::uint64_t C>
struct Mod {
    using U = UInt<L>;
    static U modulus()
    {
        U r;
        for (auto& x : r.v)
            x = UINT64_MAX;
        r.v[0] -= C - 1;
        return r;
    }
    static U normalize(U a) { return a >= modulus() ? a - modulus() : a; }
    static U reduce(const std::array<std::uint64_t, 2 * L>& t)
    {
        U r;
        Wide carry = 0;
        for (std::size_t i = 0; i < L; ++i) {
            carry = Wide(t[L + i]) * C + t[i] + std::uint64_t(carry >> 64);
            r.v[i] = std::uint64_t(carry);
        }
        carry = Wide(std::uint64_t(carry >> 64)) * C;
        for (std::size_t i = 0; i < L; ++i) {
            carry += r.v[i];
            r.v[i] = std::uint64_t(carry);
            carry >>= 64;
        }
        // If the second fold overflowed, adding C cannot overflow again.
        if (carry) r = r + U(C);
        return normalize(r);
    }
    // Forced inline: otherwise gcc may leave every multiply in
    // FixedExponent::pair's loop as a call.
    __attribute__((always_inline)) static U mul(const U& a, const U& b)
    {
#ifdef BC3_MULX4
        if constexpr (L == 4) {
            U r;
#ifdef BC3_ASM_MUL4
            r.v = mulmod_asm<C>(a.v.data(), b.v.data());
#else
            r.v = reducex4<C>(mulx4(a.v, b.v));
#endif
            return r;
        }
#endif
        return mul_rows(a, b);
    }
    // Portable row-wise product. FixedPower uses it even where mul takes the
    // mulx path: gcc overlaps its two table chains far better with it.
    static U mul_rows(const U& a, const U& b)
    {
        std::array<std::uint64_t, 2 * L> t{};
        for (std::size_t i = 0; i < L; ++i) {
            Wide carry = 0;
            for (std::size_t j = 0; j < L; ++j) {
                carry = Wide(a.v[i]) * b.v[j] + t[i + j] + std::uint64_t(carry >> 64);
                t[i + j] = std::uint64_t(carry);
            }
            t[i + L] = std::uint64_t(carry >> 64);
        }
        return reduce(t);
    }
    __attribute__((always_inline)) static U square(const U& a) { return mul(a, a); }
    // Sliding window, exponent is public and fixed for these calls.
    static U pow(U a, const U& e)
    {
        a = normalize(a);
        std::array<U, 8> odd;
        odd[0] = a;
        const U a2 = square(a);
        for (unsigned i = 1; i < 8; ++i)
            odd[i] = mul(odd[i - 1], a2);
        U r(1);
        int i = int(64 * L) - 1;
        while (i >= 0) {
            if (((e.v[unsigned(i) / 64] >> (unsigned(i) % 64)) & 1) == 0) {
                r = square(r);
                --i;
                continue;
            }
            int low = i > 3 ? i - 3 : 0;
            while (((e.v[unsigned(low) / 64] >> (unsigned(low) % 64)) & 1) == 0)
                ++low;
            unsigned index = 0;
            for (int j = i; j >= low; --j) {
                index = (index << 1) | unsigned((e.v[unsigned(j) / 64] >> (unsigned(j) % 64)) & 1);
                r = square(r);
            }
            r = mul(r, odd[index / 2]);
            i = low - 1;
        }
        return r;
    }
};
using M64 = Mod<1, 59>;
using M128 = Mod<2, 159>;
using M256 = Mod<4, 189>;
using F64 = Mod<1, 1469>;
using F128 = Mod<2, 15449>;
using F256 = Mod<4, 36113>;
// Build the sliding-window schedule at compile time. Paired evaluation exposes
// two independent carry chains to the CPU; it does not create worker threads.
template <class M, unsigned Window = 4>
struct FixedExponent {
    using U = typename M::U;
    struct Step {
        unsigned squares, index;
    };
    std::array<Step, sizeof(U) * 8> steps{};
    unsigned count = 0, tail = 0;
    explicit FixedExponent(const U& exponent)
    {
        int i = int(sizeof(U) * 8) - 1;
        auto bit = [&](int n) { return unsigned((exponent.v[unsigned(n) / 64] >> (unsigned(n) % 64)) & 1); };
        while (i >= 0 && !bit(i))
            --i;
        while (i >= 0) {
            if (!bit(i)) {
                ++tail;
                --i;
                continue;
            }
            int low = i >= int(Window - 1) ? i - int(Window - 1) : 0;
            while (!bit(low))
                ++low;
            unsigned value = 0;
            for (int j = i; j >= low; --j)
                value = (value << 1) | bit(j);
            steps[count++] = {tail + unsigned(i - low + 1), value / 2};
            tail = 0;
            i = low - 1;
        }
    }
    U operator()(U a) const
    {
        if (!count) return U(1);
        std::array<U, 1u << (Window - 1)> odd;
        odd[0] = M::normalize(a);
        const U a2 = M::square(odd[0]);
        for (unsigned i = 1; i < odd.size(); ++i)
            odd[i] = M::mul(odd[i - 1], a2);
        U r = odd[steps[0].index];
        for (unsigned i = 1; i < count; ++i) {
            for (unsigned j = 0; j < steps[i].squares; ++j)
                r = M::square(r);
            r = M::mul(r, odd[steps[i].index]);
        }
        for (unsigned i = 0; i < tail; ++i)
            r = M::square(r);
        return r;
    }
    std::pair<U, U> pair(U a, U b) const
    {
        if (!count) return {U(1), U(1)};
        std::array<U, 1u << (Window - 1)> odda, oddb;
        odda[0] = M::normalize(a);
        oddb[0] = M::normalize(b);
        const U a2 = M::square(odda[0]), b2 = M::square(oddb[0]);
        for (unsigned i = 1; i < odda.size(); ++i) {
            odda[i] = M::mul(odda[i - 1], a2);
            oddb[i] = M::mul(oddb[i - 1], b2);
        }
        U r = odda[steps[0].index], s = oddb[steps[0].index];
        for (unsigned i = 1; i < count; ++i) {
            for (unsigned j = 0; j < steps[i].squares; ++j) {
                r = M::square(r);
                s = M::square(s);
            }
            r = M::mul(r, odda[steps[i].index]);
            s = M::mul(s, oddb[steps[i].index]);
        }
        for (unsigned i = 0; i < tail; ++i) {
            r = M::square(r);
            s = M::square(s);
        }
        return {r, s};
    }
};
// g^x = product table[position][byte]. Tables are immutable and shared.
template <class M>
struct alignas(64) FixedPower {
    using U = typename M::U;
    static constexpr std::size_t bytes = sizeof(U);
    std::array<std::array<U, 256>, bytes> table;
    explicit FixedPower(U base)
    {
        for (auto& row : table) {
            row[0] = U(1);
            row[1] = base;
            for (unsigned j = 2; j < 256; ++j)
                row[j] = M::mul(row[j - 1], base);
            base = M::mul(row[255], base);
        }
    }
    U operator()(const U& e) const
    {
        U r = table[0][e.byte(0)];
        for (std::size_t i = 1; i < bytes; ++i)
            r = M::mul_rows(r, table[i][e.byte(i)]);
        return r;
    }
    std::pair<U, U> pair(const U& a, const U& b) const
    {
        U r = table[0][a.byte(0)], s = table[0][b.byte(0)];
        for (std::size_t i = 1; i < bytes; ++i) {
            r = M::mul_rows(r, table[i][a.byte(i)]);
            s = M::mul_rows(s, table[i][b.byte(i)]);
        }
        return {r, s};
    }
};
} } // namespace bc3::detail
