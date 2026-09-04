// Prototypes for the algo registration functions called by
// register_algo_gate() in algo-gate-api.c.
//
// Each is defined in that algo's own -gate.c and declared in its -gate.h, but
// algo-gate-api.c cannot include a hundred gate headers, so the switch used to
// rely on implicit declarations and a pragma to silence the warning. C23 removed
// implicit declarations, so a current clang -- Termux's, for one -- rejects the
// switch outright. Declaring them here fixes that and also makes the bool return
// value real rather than an implicit int.
//
// Generated from the definitions; keep in step when adding an algo.
#ifndef ALGO_REGISTRATIONS_H__
#define ALGO_REGISTRATIONS_H__ 1

#include "algo-gate-api.h"

bool register_allium_algo( algo_gate_t *gate );
bool register_anime_algo( algo_gate_t *gate );
bool register_argon2d250_algo( algo_gate_t *gate );
bool register_argon2d500_algo( algo_gate_t *gate );
bool register_argon2d1000_algo( algo_gate_t *gate );
bool register_argon2d16000_algo( algo_gate_t *gate );
bool register_argon2d4096_algo( algo_gate_t *gate );
bool register_argon2id1024_algo( algo_gate_t *gate );
bool register_axiom_algo( algo_gate_t *gate );
bool register_balloon_algo( algo_gate_t *gate );
bool register_blake_algo( algo_gate_t *gate );
bool register_blake2b_algo( algo_gate_t *gate );
bool register_blake2s_algo( algo_gate_t *gate );
bool register_blakecoin_algo( algo_gate_t *gate );
bool register_bmw512_algo( algo_gate_t *gate );
bool register_c11_algo( algo_gate_t *gate );
bool register_curvehash_algo( algo_gate_t *gate );
bool register_deep_algo( algo_gate_t *gate );
bool register_dmd_gr_algo( algo_gate_t *gate );
bool register_equihash_algo( algo_gate_t *gate );
bool register_equihash96_algo( algo_gate_t *gate );
bool register_equihash125_algo( algo_gate_t *gate );
bool register_equihash144_algo( algo_gate_t *gate );
bool register_equihash192_algo( algo_gate_t *gate );
bool register_flex_algo( algo_gate_t *gate );
bool register_gr_algo( algo_gate_t *gate );
bool register_groestl_algo( algo_gate_t *gate );
bool register_heavyhash_algo( algo_gate_t *gate );
bool register_hex_algo( algo_gate_t *gate );
bool register_hmq1725_algo( algo_gate_t *gate );
bool register_hoohashv110_algo( algo_gate_t *gate );
bool register_jha_algo( algo_gate_t *gate );
bool register_keccak_algo( algo_gate_t *gate );
bool register_k12_algo( algo_gate_t *gate );
bool register_keccakc_algo( algo_gate_t *gate );
bool register_lbry_algo( algo_gate_t *gate );
bool register_lyra2h_algo( algo_gate_t *gate );
bool register_lyra2re_algo( algo_gate_t *gate );
bool register_lyra2rev2_algo( algo_gate_t *gate );
bool register_lyra2rev3_algo( algo_gate_t *gate );
bool register_lyra2z_algo( algo_gate_t *gate );
bool register_lyra2z330_algo( algo_gate_t *gate );
bool register_m7m_algo( algo_gate_t *gate );
bool register_megabtx_algo( algo_gate_t *gate );
bool register_megamec_algo( algo_gate_t *gate );
bool register_mike_algo( algo_gate_t *gate );
bool register_minotaur_algo( algo_gate_t *gate );
bool register_myriad_algo( algo_gate_t *gate );
bool register_neoscrypt_algo( algo_gate_t *gate );
bool register_neoscrypt_xaya_algo( algo_gate_t *gate );
bool register_nist5_algo( algo_gate_t *gate );
bool register_odo_algo( algo_gate_t *gate );
bool register_pentablake_algo( algo_gate_t *gate );
bool register_phi1612_algo( algo_gate_t *gate );
bool register_phi2_algo( algo_gate_t *gate );
bool register_polytimos_algo( algo_gate_t *gate );
bool register_power2b_algo( algo_gate_t *gate );
bool register_quark_algo( algo_gate_t *gate );
bool register_qubit_algo( algo_gate_t *gate );
bool register_randomx_algo( algo_gate_t *gate );
bool register_rinhash_algo( algo_gate_t *gate );
bool register_scrypt_algo( algo_gate_t *gate );
bool register_sha256csm_algo( algo_gate_t *gate );
bool register_sha256d_algo( algo_gate_t *gate );
bool register_sha256dt_algo( algo_gate_t *gate );
bool register_sha256dv_algo( algo_gate_t *gate );
bool register_sha256q_algo( algo_gate_t *gate );
bool register_sha256t_algo( algo_gate_t *gate );
bool register_sha3d_algo( algo_gate_t *gate );
bool register_sha3t_algo( algo_gate_t *gate );
bool register_sha512256d_algo( algo_gate_t *gate );
bool register_skein_algo( algo_gate_t *gate );
bool register_skein2_algo( algo_gate_t *gate );
bool register_skunk_algo( algo_gate_t *gate );
bool register_skydoge_algo( algo_gate_t *gate );
bool register_sonoa_algo( algo_gate_t *gate );
bool register_soterg_algo( algo_gate_t *gate );
bool register_timetravel_algo( algo_gate_t *gate );
bool register_timetravel10_algo( algo_gate_t *gate );
bool register_tribus_algo( algo_gate_t *gate );
bool register_vanilla_algo( algo_gate_t *gate );
bool register_veltor_algo( algo_gate_t *gate );
bool register_verthash_algo( algo_gate_t *gate );
bool register_verus_algo( algo_gate_t *gate );
bool register_whirlpool_algo( algo_gate_t *gate );
bool register_whirlpoolx_algo( algo_gate_t *gate );
bool register_whirlpoolx2_algo( algo_gate_t *gate );
bool register_x11_algo( algo_gate_t *gate );
bool register_x11evo_algo( algo_gate_t *gate );
bool register_x11gost_algo( algo_gate_t *gate );
bool register_x12_algo( algo_gate_t *gate );
bool register_x13_algo( algo_gate_t *gate );
bool register_x13bcd_algo( algo_gate_t *gate );
bool register_x13sm3_algo( algo_gate_t *gate );
bool register_x14_algo( algo_gate_t *gate );
bool register_x15_algo( algo_gate_t *gate );
bool register_x16r_algo( algo_gate_t *gate );
bool register_x16rv2_algo( algo_gate_t *gate );
bool register_x16rt_algo( algo_gate_t *gate );
bool register_x16rt_veil_algo( algo_gate_t *gate );
bool register_x16s_algo( algo_gate_t *gate );
bool register_x17_algo( algo_gate_t *gate );
bool register_x20r_algo( algo_gate_t *gate );
bool register_x21s_algo( algo_gate_t *gate );
bool register_x22i_algo( algo_gate_t *gate );
bool register_x25x_algo( algo_gate_t *gate );
bool register_xevan_algo( algo_gate_t *gate );
bool register_yescrypt_algo( algo_gate_t *gate );
bool register_yescryptr8_algo( algo_gate_t *gate );
bool register_yescryptr8g_algo( algo_gate_t *gate );
bool register_yescryptr16_algo( algo_gate_t *gate );
bool register_yescryptr32_algo( algo_gate_t *gate );
bool register_yespower_algo( algo_gate_t *gate );
bool register_yespoweradvc_algo( algo_gate_t *gate );
bool register_yespowereqpay_algo( algo_gate_t *gate );
bool register_yespowerltncg_algo( algo_gate_t *gate );
bool register_yespowermgpc_algo( algo_gate_t *gate );
bool register_yespowerr16_algo( algo_gate_t *gate );
bool register_yespowersugar_algo( algo_gate_t *gate );
bool register_yespowertide_algo( algo_gate_t *gate );
bool register_yespowerurx_algo( algo_gate_t *gate );
bool register_yespower_b2b_algo( algo_gate_t *gate );
bool register_zr5_algo( algo_gate_t *gate );

#endif  // ALGO_REGISTRATIONS_H__
