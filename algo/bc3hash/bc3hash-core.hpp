#ifndef BC3_CORE_HPP
#define BC3_CORE_HPP
#include <array>
#include <cstddef>
#include <cstdint>

// Default curve table window; -a bc3hash:W (10..20) overrides it at runtime.
// 10 -> ~6.7 MiB of tables, 16 -> ~262 MiB, 20 -> ~3.1 GiB. Same digests at any W.
#ifndef BC3_CURVE_WINDOW
#define BC3_CURVE_WINDOW 16
#endif

// Nonces hashed in lockstep per scan step, sharing their field inversions.
// At most 16 (bc3hash-gate.c's buffers).
#ifndef BC3HASH_LANES
#define BC3HASH_LANES 16
#endif

namespace bc3 {
using Digest = std::array<std::uint8_t, 32>;
using Block512 = std::array<std::uint8_t, 64>;
} // namespace bc3
#endif
