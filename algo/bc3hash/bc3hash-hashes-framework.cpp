/* bc3::standard:: on this tree's sph_* hashes (map in bc3hash-hashes.hpp).
 * The SHA3 padding and the BLAKE2 PERSONAL words are pinned by the mainnet
 * vectors in bc3hash-kat.h. */
#include "bc3hash-hashes.hpp"

#include <stdexcept>

namespace bc3 {
namespace standard {

Sha3::Sha3(unsigned bits) : ctx_(), bits_(bits)
{
    switch (bits) {
        case 256: sph_keccak256_init(&ctx_); break;
        case 384: sph_keccak384_init(&ctx_); break;
        case 512: sph_keccak512_init(&ctx_); break;
        default: throw std::invalid_argument("SHA3 output size");
    }
}

void Sha3::update(const void* data, std::size_t n)
{
    if (!n)
        return;
    switch (bits_) {
        case 256: sph_keccak256(&ctx_, data, n); break;
        case 384: sph_keccak384(&ctx_, data, n); break;
        case 512: sph_keccak512(&ctx_, data, n); break;
        default: break;
    }
}

void Sha3::finish(std::uint8_t* out)
{
    switch (bits_) {
        case 256: sph_keccak256_close(&ctx_, out); break;
        case 384: sph_keccak384_close(&ctx_, out); break;
        case 512: sph_keccak512_close(&ctx_, out); break;
        default: break;
    }
}

Sha512::Sha512() : ctx_()
{
    sph_sha512_init(&ctx_);
}

void Sha512::update(const void* data, std::size_t n)
{
    if (n)
        sph_sha512(&ctx_, data, n);
}

std::array<std::uint8_t, 64> Sha512::finish()
{
    std::array<std::uint8_t, 64> out;
    sph_sha512_close(&ctx_, out.data());
    return out;
}

Ripemd160::Ripemd160() : ctx_()
{
    sph_ripemd160_init(&ctx_);
}

void Ripemd160::update(const void* data, std::size_t n)
{
    if (n)
        sph_ripemd160(&ctx_, data, n);
}

std::array<std::uint8_t, 20> Ripemd160::finish()
{
    std::array<std::uint8_t, 20> out;
    sph_ripemd160_close(&ctx_, out.data());
    return out;
}

template <class Word>
Blake2<Word>::Blake2(const std::array<std::uint8_t, 2 * sizeof(Word)>& personal)
{
    if constexpr (sizeof(Word) == 4)
        bc3_blake2s_init_pers(&ctx_.s, 32, personal.data());
    else
        bc3_blake2b_init_pers(&ctx_.s, 64, personal.data());
}

template <class Word>
void Blake2<Word>::update(const void* data, std::size_t n)
{
    if (!n)
        return;
    if constexpr (sizeof(Word) == 4)
        blake2s_update(&ctx_.s, static_cast<const std::uint8_t*>(data), n);
    else
        sph_blake2b_update(&ctx_.s, data, n);
}

template <class Word>
std::array<std::uint8_t, 8 * sizeof(Word)> Blake2<Word>::finish()
{
    std::array<std::uint8_t, 8 * sizeof(Word)> out;
    if constexpr (sizeof(Word) == 4)
        blake2s_final(&ctx_.s, out.data(), 32);
    else
        sph_blake2b_final(&ctx_.s, out.data());
    return out;
}

/* The two explicit instantiations BC3 actually needs. Paired with the
 * `extern template` lines in the header so core.cpp never instantiates its own
 * copy of bodies it cannot see. */
template class Blake2<std::uint32_t>;
template class Blake2<std::uint64_t>;

} } // namespace bc3::standard
