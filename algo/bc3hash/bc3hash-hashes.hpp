/* The coin's standard-hash interface, implemented on this tree's libraries:
 *
 *   SHA3-512/384/256  algo/keccak/sph_keccak.c  + hard_coded_eb = 6
 *   SHA-512           algo/sha/sph_sha2big.c
 *   RIPEMD-160        algo/ripemd/sph_ripemd.c
 *   BLAKE2s/BLAKE2b   algo/blake/sph-blake2s.c, sph_blake2b.c + bc3hash-impl.h
 *
 * Bodies are in bc3hash-hashes-framework.cpp. */
#ifndef BC3_HASHES_HPP
#define BC3_HASHES_HPP

#include <array>
#include <cstddef>
#include <cstdint>

/* These two headers have no __cplusplus guard of their own. */
extern "C" {
#include "algo/sha/sph_sha2.h"
#include "algo/ripemd/sph_ripemd.h"
}

#include "algo/keccak/sph_keccak.h"
#include "algo/blake/sph_blake2b.h"
#include "algo/blake/sph-blake2s.h"
#include "bc3hash-impl.h"

namespace bc3 {
namespace standard {

class Sha3
{
    sph_keccak_context ctx_;
    unsigned bits_;

public:
    explicit Sha3(unsigned output_bits);
    void update(const void*, std::size_t);
    void finish(std::uint8_t*);
};

class Sha512
{
    sph_sha512_context ctx_;

public:
    Sha512();
    void update(const void*, std::size_t);
    std::array<std::uint8_t, 64> finish();
};

class Ripemd160
{
    sph_ripemd160_context ctx_;

public:
    Ripemd160();
    void update(const void*, std::size_t);
    std::array<std::uint8_t, 20> finish();
};

/* One context type per word width. */
template <class Word>
struct Blake2Ctx;

template <>
struct Blake2Ctx<std::uint32_t> { blake2s_state s; };

template <>
struct Blake2Ctx<std::uint64_t> { sph_blake2b_ctx s; };

template <class Word>
class Blake2
{
    Blake2Ctx<Word> ctx_;

public:
    explicit Blake2(const std::array<std::uint8_t, 2 * sizeof(Word)>& personal);
    void update(const void*, std::size_t);
    std::array<std::uint8_t, 8 * sizeof(Word)> finish();
};

using Blake2s = Blake2<std::uint32_t>;
using Blake2b = Blake2<std::uint64_t>;

/* Instantiated once, in bc3hash-hashes-framework.cpp. Without these the
   member bodies -- which live in that other TU -- get implicitly instantiated
   into every BC3 worker and the link picks one arbitrarily. */
extern template class Blake2<std::uint32_t>;
extern template class Blake2<std::uint64_t>;

} } // namespace bc3::standard
#endif
