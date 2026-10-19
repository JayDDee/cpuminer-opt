#include "bc3hash-core.hpp"
#include "bc3hash-constants.hpp"
#include "bc3hash-uint.hpp"
#include "bc3hash-hashes.hpp"
#include "bc3hash-ec.h"
#include "bc3hash-ifma.hpp"
#include <secp256k1.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace bc3 {
namespace detail {
using namespace constants;
namespace {
// Set at runtime by -a bc3hash:W. Frozen once the tables exist, since they are
// sized for the window they were built at.
unsigned curve_window = BC3_CURVE_WINDOW;
bool tables_frozen = false;

unsigned active_window()
{
    return curve_window;
}
const FixedExponent<M64, 3> exp64(E64);
const FixedExponent<M128, 4> exp128(E128);
const FixedExponent<M256, 4> exp256(E256);
// secp256k1 group order, parsed once (U256::hex is not constexpr).
const U256 curve_order = U256::hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
bc3ec_affine to_affine(const U256& x, const U256& y)
{
    bc3ec_affine a;
    for (unsigned i = 0; i < 4; ++i) {
        a.x[i] = x.v[i];
        a.y[i] = y.v[i];
    }
    return a;
}
std::pair<U256, U256> from_affine(const bc3ec_affine& a)
{
    std::pair<U256, U256> r;
    for (unsigned i = 0; i < 4; ++i) {
        r.first.v[i] = a.x[i];
        r.second.v[i] = a.y[i];
    }
    return r;
}
struct alignas(64) CurveTable {
    const unsigned window = active_window();
    const unsigned digits = (256 + window - 1) / window;
    const unsigned entries = (1u << window) - 1;
    const unsigned last_entries = (1u << (256 - window * (digits - 1))) - 1;
    // Each affine point (bc3hash-ec.c storage form) occupies one cache line.
    // The final window has fewer bits; omit unreachable entries instead of
    // padding that row. C++17 aligned new lets std::vector honour the alignas.
    struct alignas(64) Key {
        unsigned char value[BC3EC_ENTRY_BYTES];
    };
    static_assert(sizeof(Key) == 64, "one cache line per table entry");
    std::vector<Key> table;
    const U256 base_x, base_y;
    CurveTable(U256 x, U256 y) : table((digits - 1) * entries + last_entries), base_x(x), base_y(y)
    {
        static_assert(BC3EC_MAX_POINTS * 10 >= 256, "26 digits at window 10");
        bc3ec_affine base = to_affine(x, y), next;
        for (unsigned i = 0; i < digits; ++i) {
            const bool last = i + 1 == digits;
            const int rc = bc3ec_row(table.data() + i * entries, last ? last_entries : entries, &base, last ? nullptr : &next);
            if (rc == -2) throw std::bad_alloc();
            if (rc) throw std::runtime_error("Invalid BC3 curve constant");
            if (!last) base = next;
        }
    }
    // Table entries summing to k*P, prefetched; 0 when k = 0 (mod n).
    unsigned points(U256 k, const void** pts) const
    {
        if (k >= curve_order) k = k - curve_order;
        if (k.zero()) return 0;
        unsigned n = 0;
        for (unsigned i = 0; i < digits; ++i) {
            const unsigned pos = i * window, limb = pos / 64, shift = pos % 64;
            std::uint64_t b = k.v[limb] >> shift;
            if (shift && limb + 1 < 4) b |= k.v[limb + 1] << (64 - shift);
            b &= entries;
            if (b) {
                pts[n] = table[i * entries + b - 1].value;
                // Issue independent cache misses together, ahead of the
                // dependent sequence of elliptic-curve additions.
                __builtin_prefetch(pts[n], 0, 3);
                ++n;
            }
        }
        return n;
    }
    std::pair<U256, U256> operator()(U256 k) const
    {
        const void* pts[1][BC3EC_MAX_POINTS];
        unsigned n = points(k, pts[0]);
        if (!n) return {INVALID_POINT_x, INVALID_POINT_y};
        bc3ec_affine r;
        if (bc3ec_sum(&r, pts, &n, 1)) throw std::runtime_error("BC3 point combination failed");
        return from_affine(r);
    }
};
struct Tables {
    FixedPower<F64> pow64{g64};
    FixedPower<F128> pow128{g128};
    FixedPower<F256> pow256{g256};
    std::array<CurveTable, 4> curve{{{H_x, H_y}, {J_x, J_y}, {K_x, K_y}, {L_x, L_y}}};
};
// k[i]*P_(i%4) for M scalars at once; each bc3ec_sum call shares one
// inversion across up to BC3EC_MAX_SUMS of them.
template <std::size_t M>
std::array<std::pair<U256, U256>, M> curve_mult(const Tables& t, const std::array<U256, M>& k)
{
    std::array<std::pair<U256, U256>, M> r;
    for (std::size_t base = 0; base < M; base += BC3EC_MAX_SUMS) {
        const void* pts[BC3EC_MAX_SUMS][BC3EC_MAX_POINTS];
        unsigned n[BC3EC_MAX_SUMS], slot[BC3EC_MAX_SUMS], sums = 0;
        for (std::size_t i = base; i < M && i < base + BC3EC_MAX_SUMS; ++i) {
            n[sums] = t.curve[i % 4].points(k[i], pts[sums]);
            if (n[sums])
                slot[sums++] = unsigned(i);
            else
                r[i] = {INVALID_POINT_x, INVALID_POINT_y};
        }
        if (sums) {
            bc3ec_affine a[BC3EC_MAX_SUMS];
            if (bc3ec_sum(a, pts, n, sums)) throw std::runtime_error("BC3 point combination failed");
            for (unsigned s = 0; s < sums; ++s)
                r[slot[s]] = from_affine(a[s]);
        }
    }
    return r;
}
std::array<std::pair<U256, U256>, 4> curve_mult4(const Tables& t, const std::array<U256, 4>& k)
{
    return curve_mult<4>(t, k);
}
const Tables& tables()
{
    // Never destroyed, same reason as context(): exit() runs static destructors
    // while miner threads still read the tables.
    static const Tables& t = *new Tables;
    return t;
}
// k*P through curvehash's 2015 libsecp256k1, whose own scalar multiplication
// (ecmult) shares nothing with the tables or bc3hash-ec.c.
std::pair<U256, U256> reference_mult(const secp256k1_context* ctx, const CurveTable& c, U256 k)
{
    if (k >= curve_order) k = k - curve_order;
    if (k.zero()) return {INVALID_POINT_x, INVALID_POINT_y};
    std::array<unsigned char, 65> encoded{};
    std::array<unsigned char, 32> scalar;
    encoded[0] = 4;
    c.base_x.store(encoded.data() + 1);
    c.base_y.store(encoded.data() + 33);
    k.store(scalar.data());
    secp256k1_pubkey point;
    std::size_t length = encoded.size();
    if (!secp256k1_ec_pubkey_parse(ctx, &point, encoded.data(), 65) ||
        !secp256k1_ec_pubkey_tweak_mul(ctx, &point, scalar.data()) ||
        !secp256k1_ec_pubkey_serialize(ctx, encoded.data(), &length, &point, SECP256K1_EC_UNCOMPRESSED))
        throw std::runtime_error("BC3 reference point operation failed");
    return {U256::load(encoded.data() + 1), U256::load(encoded.data() + 33)};
}
// Startup differential against reference_mult on every table, through every
// batch width mining uses: a wrong table entry or kernel only shows for the
// scalars that reach it, so the KAT alone is not enough.
bool ec_self_test(const Tables& t)
{
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) throw std::bad_alloc();
    const unsigned w = t.curve[0].window;
    U256 ones;
    ones.v = {~0ULL, ~0ULL, ~0ULL, ~0ULL};
    std::vector<U256> ks = {U256(1), U256(2), U256(3), U256((1ULL << w) - 1), U256(1ULL << w),
                            U256((1ULL << w) + 1), curve_order - U256(1), curve_order - U256(2),
                            curve_order, curve_order + U256(1), ones, U256{}};
    std::uint64_t s = 0x9e3779b97f4a7c15ULL;
    for (unsigned i = 0; i < 40; ++i) {
        U256 k;
        for (auto& x : k.v) {
            s += 0x9e3779b97f4a7c15ULL; // splitmix64
            std::uint64_t z = s;
            z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
            z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
            x = z ^ (z >> 31);
        }
        ks.push_back(k);
    }
    // Also one digit value in every row at once: row ends and bc3ec_row's
    // chunk boundaries, which random scalars rarely reach.
    const auto& c0 = t.curve[0];
    for (unsigned d : {1u, 2u, 4095u, 4096u, 4097u, 8192u, c0.entries - 1, c0.entries}) {
        if (d > c0.entries) continue;
        U256 k;
        for (unsigned i = 0; i < c0.digits; ++i) {
            const unsigned pos = i * w, limb = pos / 64, shift = pos % 64;
            const std::uint64_t v = d & (i + 1 == c0.digits ? c0.last_entries : c0.entries);            k.v[limb] |= v << shift;
            if (shift + w > 64 && limb + 1 < 4) k.v[limb + 1] |= v >> (64 - shift);
        }
        ks.push_back(k);
    }
    bool ok = true;
    try {
        for (std::size_t i = 0; i < ks.size() && ok; ++i) {
            std::array<U256, 4> k;
            for (unsigned c = 0; c < 4; ++c)
                k[c] = ks[(i + c) % ks.size()];
            const auto got = curve_mult4(t, k);
            for (unsigned c = 0; c < 4; ++c) {
                const auto want = reference_mult(ctx, t.curve[c], k[c]);
                ok = ok && got[c] == want && t.curve[c](k[c]) == want;
            }
        }
        // Mining-width batches (bc3ec_sum's 8-sum paths), mixed digit counts.
        for (std::size_t i = 0; i < ks.size() && ok; i += 3) {
            std::array<U256, BC3EC_MAX_SUMS> k;
            for (unsigned c = 0; c < BC3EC_MAX_SUMS; ++c)
                k[c] = ks[(i + 5 * c) % ks.size()];
            const auto got = curve_mult<BC3EC_MAX_SUMS>(t, k);
            for (unsigned c = 0; c < BC3EC_MAX_SUMS; ++c)
                ok = ok && got[c] == reference_mult(ctx, t.curve[c % 4], k[c]);
        }
    } catch (...) {
        secp256k1_context_destroy(ctx);
        throw;
    }
    secp256k1_context_destroy(ctx);
    return ok;
}
// Coefficients stay in [0,p). This is variable-time arithmetic on public
// hash inputs, never a secret-key primitive.
U256 shift_right(U256 x, unsigned n)
{
    if (n == 64) {
        x.v = {x.v[1], x.v[2], x.v[3], 0};
        return x;
    }
    for (unsigned i = 0; i < 3; ++i)
        x.v[i] = (x.v[i] >> n) | (x.v[i + 1] << (64 - n));
    x.v[3] >>= n;
    return x;
}
// Compile-time, not a function-local static: divide_power2_mod sits inside
// inverse256()'s binary-Euclid loop, so a static there is a guard branch per
// iteration. Same six Newton steps, folded at compile time.
constexpr std::uint64_t inverse_odd64(std::uint64_t x)
{
    std::uint64_t y = 1;
    for (unsigned i = 0; i < 6; ++i)
        y *= 2 - x * y;
    return y;
}
constexpr std::uint64_t inv36113 = inverse_odd64(36113);
U256 divide_power2_mod(U256 x, unsigned n)
{
    // Choose q so x + q*p is divisible by 2^n. For p=2^256-C,
    // q = x/C (mod 2^n). x+q*p = (x-q*C) + q*2^256.
    auto q = x.v[0] * inv36113;
    if (n < 64) q &= (std::uint64_t{1} << n) - 1;
    const Wide product = Wide(q) * 36113;
    U256 correction;
    correction.v[0] = std::uint64_t(product);
    correction.v[1] = std::uint64_t(product >> 64);
    const bool borrow = x < correction;
    x = shift_right(x - correction, n);
    x.v[3] |= (q - std::uint64_t(borrow)) << (64 - n);
    return x;
}
U256 subtract_mod(U256 x, U256 y)
{
    return x >= y ? x - y : F256::modulus() - (y - x);
}
U256 scale_mod(U256 x, std::int64_t factor)
{
    const bool negative = factor < 0;
    const auto magnitude = std::uint64_t(negative ? -factor : factor);
    Wide carry = 0;
    for (unsigned i = 0; i < 4; ++i) {
        carry = Wide(x.v[i]) * magnitude + std::uint64_t(carry >> 64);
        x.v[i] = std::uint64_t(carry);
    }
    carry = Wide(std::uint64_t(carry >> 64)) * 36113;
    for (unsigned i = 0; i < 4; ++i) {
        carry += x.v[i];
        x.v[i] = std::uint64_t(carry);
        carry >>= 64;
    }
    if (carry) x = x + U256(36113);
    x = F256::normalize(x);
    return negative && !x.zero() ? F256::modulus() - x : x;
}
U256 add_mod(U256 x, U256 y)
{
    const auto sum = x + y;
    return F256::normalize(sum + (sum < x ? U256(36113) : U256{}));
}
UInt<5> scale_wide(U256 x, std::int64_t factor)
{
    UInt<5> r;
    Wide carry = 0;
    const auto magnitude = std::uint64_t(factor < 0 ? -factor : factor);
    for (unsigned i = 0; i < 4; ++i) {
        carry = Wide(x.v[i]) * magnitude + std::uint64_t(carry >> 64);
        r.v[i] = std::uint64_t(carry);
    }
    r.v[4] = std::uint64_t(carry >> 64);
    return r;
}
U256 linear_positive(U256 u, U256 v, std::int64_t a, std::int64_t b)
{
    const auto au = scale_wide(u, a), bv = scale_wide(v, b);
    return U256(a < 0 ? bv - au : b < 0 ? au - bv :
                                          au + bv);
}
bool euclid_batch(U256& u, U256& v, U256& x, U256& y)
{
    // Infer several exact Euclidean quotients from intervals around the top
    // 62 bits. The omitted low bits lie in [0,1); interval agreement proves
    // the quotient, including when signed matrix coefficients change sides.
    unsigned high = 3;
    while (high && !(u.v[high] | v.v[high]))
        --high;
    if (high == 0) return false;
    const unsigned bits = 64 - unsigned(__builtin_clzll(u.v[high] | v.v[high]));
    const unsigned shift = bits > 62 ? bits - 62 : 0;
    std::uint64_t top_u, top_v;
    if (bits >= 62) {
        top_u = u.v[high] >> shift;
        top_v = v.v[high] >> shift;
    } else {
        top_u = (u.v[high] << (62 - bits)) | (u.v[high - 1] >> (bits + 2));
        top_v = (v.v[high] << (62 - bits)) | (v.v[high - 1] >> (bits + 2));
    }
    std::int64_t a = 1, b = 0, c = 0, d = 1;
    unsigned steps = 0;
    for (; steps < 32; ++steps) {
        const SignedWide nx = SignedWide(a) * top_u + SignedWide(b) * top_v;
        const SignedWide ny = SignedWide(c) * top_u + SignedWide(d) * top_v;
        const auto lx = nx + std::min<std::int64_t>(a, 0) + std::min<std::int64_t>(b, 0);
        const auto hx = nx + std::max<std::int64_t>(a, 0) + std::max<std::int64_t>(b, 0);
        const auto ly = ny + std::min<std::int64_t>(c, 0) + std::min<std::int64_t>(d, 0);
        const auto hy = ny + std::max<std::int64_t>(c, 0) + std::max<std::int64_t>(d, 0);
        if (lx < 0 || ly <= 0) break;
        // The exact remainders decrease from <=2^62; the interval error is
        // <=2^32, so these positive bounds fit in 64 bits.
        const auto q = std::uint64_t(lx) / std::uint64_t(hy);
        if (q != std::uint64_t(hx) / std::uint64_t(ly) || q > INT32_MAX) break;
        const auto next_c = SignedWide(a) - SignedWide(q) * c, next_d = SignedWide(b) - SignedWide(q) * d;
        if (next_c < -INT32_MAX || next_c > INT32_MAX || next_d < -INT32_MAX || next_d > INT32_MAX) break;
        a = c;
        b = d;
        c = std::int64_t(next_c);
        d = std::int64_t(next_d);
    }
    if (steps < 2) return false;
    const auto nu = linear_positive(u, v, a, b), nv = linear_positive(u, v, c, d);
    const auto nx = add_mod(scale_mod(x, a), scale_mod(y, b));
    y = add_mod(scale_mod(x, c), scale_mod(y, d));
    x = nx;
    u = nu;
    v = nv;
    return true;
}
} // namespace
U256 inverse256(U256 a)
{
    a = F256::normalize(a);
    if (a.zero()) return {};
    U256 u = a, v = F256::modulus(), x(1), y;
    const U256 one(1);
    // Binary extended Euclid: u = a*x and v = a*y modulo p.
    while (u != one && v != one) {
        if (!(u.v[1] | u.v[2] | u.v[3] | v.v[1] | v.v[2] | v.v[3]) && ((u.v[0] | v.v[0]) >> 62) == 0) {
            auto small_u = u.v[0], small_v = v.v[0];
            std::int64_t a0 = 1, b0 = 0, a1 = 0, b1 = 1;
            while (small_v) {
                const auto q = small_u / small_v;
                const auto remainder = small_u % small_v;
                const auto next_a = std::int64_t(SignedWide(a0) - SignedWide(q) * a1);
                const auto next_b = std::int64_t(SignedWide(b0) - SignedWide(q) * b1);
                small_u = small_v;
                small_v = remainder;
                a0 = a1;
                b0 = b1;
                a1 = next_a;
                b1 = next_b;
            }
            return add_mod(scale_mod(x, a0), scale_mod(y, b0));
        }
        if (euclid_batch(u, v, x, y)) continue;
        while (!(u.v[0] & 1)) {
            const unsigned n = u.v[0] ? unsigned(__builtin_ctzll(u.v[0])) : 64;
            u = shift_right(u, n);
            x = divide_power2_mod(x, n);
        }
        while (!(v.v[0] & 1)) {
            const unsigned n = v.v[0] ? unsigned(__builtin_ctzll(v.v[0])) : 64;
            v = shift_right(v, n);
            y = divide_power2_mod(y, n);
        }
        if (u == one || v == one) break;
        if (u >= v) {
            u = u - v;
            x = subtract_mod(x, y);
        } else {
            v = v - u;
            y = subtract_mod(y, x);
        }
    }
    return u == one ? x : y;
}
// inverse256 of N values with one inversion (Montgomery's trick). A zero
// keeps inverse256's convention (0 -> 0) and stays out of the product.
template <unsigned N>
std::array<U256, N> inverse256_lanes(const std::array<U256, N>& a)
{
    std::array<U256, N> x, prefix, r;
    U256 acc(1);
    for (unsigned l = 0; l < N; ++l) {
        x[l] = F256::normalize(a[l]);
        prefix[l] = acc;
        if (!x[l].zero()) acc = F256::mul(acc, x[l]);
    }
    U256 inv = inverse256(acc);
    for (unsigned l = N; l--;) {
        if (x[l].zero()) {
            r[l] = U256{};
            continue;
        }
        r[l] = F256::mul(inv, prefix[l]);
        inv = F256::mul(inv, x[l]);
    }
    return r;
}
// out[i] = exp256(in[i]) for n values: IFMA 16 at a time where built, else
// the scalar pair (two chains for ILP). On AVX2 builds without the mulx asm,
// gcc would inline it into mix_lanes and leave its multiplies as calls there.
#if defined(__AVX2__) && !defined(BC3_MULX4)
__attribute__((noinline))
#endif
static void exp256_many(const U256* in, U256* out, unsigned n)
{
    unsigned i = 0;
#ifdef BC3_IFMA_EXP
    for (; i + 16 <= n; i += 16)
        ifma::exp_groups<2>(exp256, in + i, out + i);
#endif
    for (; i + 2 <= n; i += 2) {
        const auto p = exp256.pair(in[i], in[i + 1]);
        out[i] = p.first;
        out[i + 1] = p.second;
    }
    if (i < n) out[i] = exp256(in[i]);
}
// BC3Mix up to the 256-bit rounds: everything there is per nonce and needs
// no batching.
struct MixFront {
    U256 h1, h2;
    std::array<U256, 16> m; // m256[48..63]
};
static void mix_front(const void* input, unsigned folded, MixFront& out)
{
    const auto& t = tables();
    const auto* bytes = static_cast<const std::uint8_t*>(input);
    std::array<U64, 32> m64;
    std::array<U128, 48> m128;
    std::array<U256, 64> m256;
    for (unsigned i = 0; i < 8; ++i)
        m64[i] = U64::load(bytes + 8 * i);
    auto c1 = m64[0] ^ base[0], c2 = m64[1] ^ base[1], c3 = m64[2] ^ base[2], c4 = m64[3] ^ base[3];
    auto c5 = m64[4] ^ base[4], c6 = m64[5] ^ base[5], c7 = m64[6] ^ base[6], c8 = m64[7] ^ base[7];
    // Same recurrence as upstream, carried in a rolling window: gcc 13 -O3
    // vectorizes the array form without -fno-strict-aliasing and gets it wrong.
    {
        std::array<U64, 8> w;
        for (unsigned i = 0; i < 8; ++i)
            w[i] = m64[i];
        for (unsigned i = 8; i < 32; ++i) {
            const U64 next = gamma(w[0], w[4]) + gamma(w[1], w[5]) + gamma(w[2], w[6]) + gamma(w[3], w[7]);
            for (unsigned j = 0; j < 7; ++j)
                w[j] = w[j + 1];
            w[7] = next;
            m64[i] = next;
        }
    }
    for (unsigned i = 24; i < 32; ++i)
        m128[i] = U128(m64[i]);
    for (unsigned i = 32; i < 48; ++i)
        m128[i] = beta(m128[i - 8]) + beta(m128[i - 7]) + beta(m128[i - 4]) + beta(m128[i - 3]);
    for (unsigned i = 41; i < 48; ++i)
        m256[i] = U256(m128[i]);
    for (unsigned i = 48; i < 64; ++i)
        m256[i] = beta(m256[i - 7]) + beta(m256[i - 6]) + beta(m256[i - 2]) + beta(m256[i - 1]);
    for (unsigned i = 0; i < 32; ++i) {
        auto powers = exp64.pair(c1 ^ sig0(c2), c3 ^ sig1(c4));
        auto d1 = powers.first + ror<7>(c6) + rol<13>(c5);
        auto d2 = powers.second + ch(c5, c6, c7) + maj(c1, c4, c8);
        auto d3 = c8 + Sig0(c7) + round64[i];
        auto d4 = c5 + Sig1(c1) + d1 + m64[i] + t.pow64(d3);
        c8 = c7 + U64(folded);
        c7 = c6 + d1 + sig0(M64::mul(d1, d3));
        c6 = c5 + sig1(d2 ^ d3);
        c5 = c4;
        c4 = c3 + d4;
        c3 = c2;
        c2 = c1 ^ d3;
        c1 = gamma(d1, d2) + (d3 ^ d4) + beta(M64::mul(d2, d4));
    }
    U128 f1, f2, f3, f4;
    f1.v = {c5.v[0], c1.v[0]};
    f2.v = {c6.v[0], c2.v[0]};
    f3.v = {c7.v[0], c3.v[0]};
    f4.v = {c8.v[0], c4.v[0]};
    for (unsigned i = 0; i < 16; ++i) {
        auto powers = exp128.pair(f1 ^ beta(f3), f2 ^ beta(f4));
        auto a = powers.first + sig0(f2 ^ f4) + ch(f2, f3, f4);
        auto b = powers.second + sig1(f1 ^ f3) + maj(f1, f2, f3);
        auto c = rol<29>(~f1) + ror<7>(~f2) + f3 + (~f4) + m128[32 + i] + t.pow128(f3);
        auto d = rol<29>(~f3) + ror<7>(f4) + f2 + (~f1) + round128[i];
        f4 = f3 + a;
        f3 = f2;
        f2 = f1 + c + beta(d);
        f1 = b + Sig0(a ^ c ^ d);
    }
    out.h1.v = {f3.v[0], f3.v[1], f1.v[0], f1.v[1]};
    out.h2.v = {f4.v[0], f4.v[1], f2.v[0], f2.v[1]};
    for (unsigned i = 0; i < 16; ++i)
        out.m[i] = m256[48 + i];
}
// BC3Mix for N inputs in lockstep. Each nonce's arithmetic is unchanged; the
// lanes share inversions: a round's 4N curve mults and each final step's k2.
template <unsigned N>
static void mix_lanes(const void* const* input, unsigned folded, Digest* out)
{
    const auto& t = tables();
    std::array<MixFront, N> s;
    for (unsigned l = 0; l < N; ++l)
        mix_front(input[l], folded, s[l]);
    for (unsigned i = 0; i < 16; ++i) {
        std::array<U256, N> j1, j2, j3, j4;
        std::array<U256, 4 * N> k;
        // Two exp256 per lane per stage, all lanes' at once: x[2l], x[2l+1].
        std::array<U256, 2 * N> x, y;
        for (unsigned l = 0; l < N; ++l) {
            const U256 h1 = s[l].h1, h2 = s[l].h2;
            x[2 * l] = rol<11>(h1) ^ h2;
            x[2 * l + 1] = h1 ^ beta(~h2);
        }
        exp256_many(x.data(), y.data(), 2 * N);
        for (unsigned l = 0; l < N; ++l) {
            const U256 h1 = s[l].h1, h2 = s[l].h2;
            j1[l] = y[2 * l] + beta(h1 ^ h2);
            j2[l] = y[2 * l + 1] + gamma(h1, h2);
            x[2 * l] = j1[l];
            x[2 * l + 1] = j2[l];
        }
        exp256_many(x.data(), y.data(), 2 * N);
        for (unsigned l = 0; l < N; ++l) {
            const U256 h1 = s[l].h1, h2 = s[l].h2;
            j3[l] = gamma(j1[l], j2[l]) + y[2 * l] + round256[i];
            j4[l] = gamma(j3[l], beta(h2)) + y[2 * l + 1] + s[l].m[i] + ch(j1[l], j2[l], j3[l]);
            // Table order H, J, K, L: k[4l + c] uses curve c (curve_mult takes i % 4).
            k[4 * l] = h1;
            k[4 * l + 1] = h2;
            k[4 * l + 2] = j1[l];
            k[4 * l + 3] = j3[l];
        }
        const auto p = curve_mult<4 * N>(t, k);
        for (unsigned l = 0; l < N; ++l) {
            const U256 j5 = p[4 * l].first, j6 = p[4 * l].second;
            const U256 j7 = p[4 * l + 1].first, j8 = p[4 * l + 1].second;
            const U256 j9 = p[4 * l + 2].first, j10 = p[4 * l + 2].second;
            const U256 j11 = p[4 * l + 3].first, j12 = p[4 * l + 3].second;
            const U256 h1 = s[l].h1;
            s[l].h2 = h1 + gamma(j1[l], j3[l]) + maj(j2[l], j3[l], j4[l]) + j5 + j8 + ch(j1[l], j6, j7) + beta(j10) + j11;
            s[l].h1 = beta(j2[l]) + gamma(j3[l], j4[l]) + Sig1(M256::mul(j1[l], j2[l])) + maj(j7, j6, j5) + Sig0(j9) + j12;
        }
    }
    std::array<U256, N> u1, u2, k1, k2;
    for (unsigned l = 0; l < N; ++l) {
        u1[l] = s[l].h1;
        u2[l] = s[l].h2 + U256(folded);
    }
    for (const auto& fc : final) {
        for (unsigned l = 0; l < N; ++l) {
            auto powers = t.pow256.pair(u1[l], u2[l]);
            k1[l] = powers.first + beta(u2[l]);
            k2[l] = powers.second + gamma(u1[l], u2[l]) + ch(k1[l], u2[l], u1[l]);
        }
        const auto inv = inverse256_lanes<N>(k2);
        for (unsigned l = 0; l < N; ++l) {
            auto k3 = inv[l] + beta(u1[l]) + beta(u2[l] ^ k1[l] ^ fc);
            u2[l] = (k1[l] ^ u1[l]) + maj(k1[l], k2[l], u2[l]) + beta(k3);
            u1[l] = beta(k1[l]) + k2[l];
        }
    }
    for (unsigned l = 0; l < N; ++l)
        (u1[l] + beta(u2[l])).store(out[l].data());
}
static Digest mix512(const void* input, unsigned folded)
{
    Digest d;
    mix_lanes<1>(&input, folded, &d);
    return d;
}
} } // namespace bc3::detail

namespace bc3 {
static const char* domain = "BC3Hash-BlockHash-Algorithm/BitcoinIII-PoW/2026";
// Derived by the exact hashlib formulas in the authoritative bc3hash.py.
constexpr std::array<std::uint8_t, 8> person_s{{0x0a, 0x20, 0xe8, 0x11, 0x61, 0x09, 0x08, 0xba}};
constexpr std::array<std::uint8_t, 16> person_b{{0x1e, 0x80, 0xf2, 0xfd, 0xdc, 0x58, 0x18, 0xd6, 0xfe, 0x9b, 0x58, 0x1e, 0x3b, 0xd4, 0x93, 0x0b}};
template <class H>
void tag(H& h, const char* suffix)
{
    h.update(domain, std::strlen(domain));
    h.update(suffix, std::strlen(suffix));
}
struct State {
    standard::Sha3 sha3_512{512}, sha3_384{384};
    standard::Sha512 sha512;
    standard::Ripemd160 ripemd;
    standard::Blake2s blake_s{person_s};
    standard::Blake2b blake_b{person_b};
    State()
    {
        tag(sha3_512, "/SHA3-512");
        tag(sha3_384, "/SHA3-384");
        tag(sha512, "/SHA-512");
        tag(ripemd, "/RIPEMD-160");
        tag(blake_s, "/BLAKE2s");
        tag(blake_b, "/BLAKE2b");
    }
    void update(const void* data, std::size_t n)
    {
        if (n && !data) throw std::invalid_argument("Null BC3 input");
        sha3_512.update(data, n);
        sha3_384.update(data, n);
        sha512.update(data, n);
        ripemd.update(data, n);
        blake_s.update(data, n);
        blake_b.update(data, n);
    }
    // BC3Mix's input.
    void preimage(Block512& p) { sha3_512.finish(p.data()); }
    Digest finish()
    {
        Block512 p;
        preimage(p);
        return finish(detail::mix512(p.data(), 0));
    }
    Digest finish(const Digest& mix)
    {
        std::array<std::uint8_t, 48> s384;
        sha3_384.finish(s384.data());
        const auto s512 = sha512.finish();
        const auto r160 = ripemd.finish();
        const auto bs = blake_s.finish();
        const auto bb = blake_b.finish();
        standard::Sha3 final{256};
        tag(final, "/SHA3-256");
        final.update(s384.data(), s384.size());
        final.update(mix.data(), mix.size());
        final.update(s512.data(), s512.size());
        final.update(r160.data(), r160.size());
        final.update(bs.data(), bs.size());
        final.update(bb.data(), bb.size());
        Digest output;
        final.finish(output.data());
        return output;
    }
};
Digest bc3hash(const void* data, std::size_t n)
{
    State state;
    state.update(data, n);
    return state.finish();
}
// N inputs of n bytes each, hashed with BC3Mix in lockstep (see mix_lanes).
template <unsigned N>
void bc3hash_lanes(const void* const* data, std::size_t n, Digest* out)
{
    std::array<State, N> state;
    std::array<Block512, N> pre;
    const void* mix_in[N];
    for (unsigned l = 0; l < N; ++l) {
        state[l].update(data[l], n);
        state[l].preimage(pre[l]);
        mix_in[l] = pre[l].data();
    }
    std::array<Digest, N> mix;
    detail::mix_lanes<N>(mix_in, 0, mix.data());
    for (unsigned l = 0; l < N; ++l)
        out[l] = state[l].finish(mix[l]);
}
} // namespace bc3

extern "C" {
/* Call before bc3_hash_init_cxx(); 0 = the default. -1 once the tables
 * exist, so the gate cannot mistake an ineffective request for success. */
int bc3_hash_set_window(unsigned window)
{
    if (bc3::detail::tables_frozen)
        return -1;
    bc3::detail::curve_window = window ? window : BC3_CURVE_WINDOW;
    return 0;
}

/* Bytes the four curve tables occupy at a given window, 0 outside the range
 * where the shifts below are defined. Kept here rather than in the C gate so
 * the sizing formula cannot drift from what the tables really allocate. */
std::uint64_t bc3_hash_table_bytes(unsigned window)
{
    if (window < 2 || window > 31)
        return 0;
    const unsigned digits = (256 + window - 1) / window;
    const std::uint64_t entries = (1ULL << window) - 1;
    const unsigned rest = 256 - window * (digits - 1);
    const std::uint64_t last = (1ULL << rest) - 1;
    return 4ULL * ((std::uint64_t)(digits - 1) * entries + last)
           * BC3EC_ENTRY_BYTES;
}

/* The window the tables will actually be built at, default included. */
unsigned bc3_hash_get_window(void)
{
    return bc3::detail::curve_window;
}

int bc3_hash_init_cxx(void)
{
    try {
        const auto& t = bc3::detail::tables();
        bc3::detail::tables_frozen = true;
        return bc3::detail::ec_self_test(t) ? 0 : -4;
    } catch (const std::bad_alloc&) { return -1; }        /* secp context / table alloc */
    catch (const std::exception&) { return -2; }         /* curve constant or point op */
    catch (...) { return -3; }
}
/* exp256 path this TU compiled to, for the startup log. */
const char* bc3_hash_exp_path(void)
{
#ifdef BC3_IFMA_EXP
    return "AVX-512 IFMA, 8 lanes x 5x52";
#else
    return "scalar";
#endif
}
/* Nonces per bc3_hash_lanes_cxx() call. */
unsigned bc3_hash_lanes(void)
{
    return BC3HASH_LANES;
}
/* BC3HASH_LANES inputs of len bytes, back to back in data; digests back to
 * back in out. Same digests as bc3_hash_cxx() on each input. */
int bc3_hash_lanes_cxx(const void* data, std::uint32_t len, unsigned char* out)
{
    if (!out || !data) return -1;
    try {
        const void* in[BC3HASH_LANES];
        for (unsigned l = 0; l < BC3HASH_LANES; ++l)
            in[l] = static_cast<const unsigned char*>(data) + std::size_t(l) * len;
        bc3::Digest d[BC3HASH_LANES];
        bc3::bc3hash_lanes<BC3HASH_LANES>(in, len, d);
        for (unsigned l = 0; l < BC3HASH_LANES; ++l)
            for (std::uint32_t i = 0; i < 32; ++i) out[32 * l + i] = d[l][i];
        return 0;
    } catch (...) { return -1; }
}
int bc3_hash_cxx(const void* data, std::uint32_t len, unsigned char* out)
{
    if (!out || (len && !data)) return -1;
    try {
        const bc3::Digest d = bc3::bc3hash(data, len);
        for (std::uint32_t i = 0; i < 32; ++i) out[i] = d[i];
        return 0;
    } catch (...) { return -1; }
}
}
