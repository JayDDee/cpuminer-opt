/*
Copyright (c) 2018-2019, tevador <tevador@gmail.com>

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
	* Redistributions of source code must retain the above copyright
	  notice, this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright
	  notice, this list of conditions and the following disclaimer in the
	  documentation and/or other materials provided with the distribution.
	* Neither the name of the copyright holder nor the
	  names of its contributors may be used to endorse or promote products
	  derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#pragma once

//Cache size in KiB. Must be a power of 2.
#ifndef RANDOMX_ARGON_MEMORY
#define RANDOMX_ARGON_MEMORY       262144
#endif

//Number of Argon2d iterations for Cache initialization.
#ifndef RANDOMX_ARGON_ITERATIONS
#define RANDOMX_ARGON_ITERATIONS   3
#endif

//Number of parallel lanes for Cache initialization.
#ifndef RANDOMX_ARGON_LANES
#define RANDOMX_ARGON_LANES        1
#endif

//Argon2d salt
#ifndef RANDOMX_ARGON_SALT
#define RANDOMX_ARGON_SALT         "RandomX\x03"
#endif

//Number of random Cache accesses per Dataset item. Minimum is 2.
#ifndef RANDOMX_CACHE_ACCESSES
#define RANDOMX_CACHE_ACCESSES     8
#endif

//Target latency for SuperscalarHash (in cycles of the reference CPU).
#ifndef RANDOMX_SUPERSCALAR_LATENCY
#define RANDOMX_SUPERSCALAR_LATENCY   170
#endif

//Dataset base size in bytes. Must be a power of 2.
#ifndef RANDOMX_DATASET_BASE_SIZE
#define RANDOMX_DATASET_BASE_SIZE  2147483648
#endif

//Dataset extra size. Must be divisible by 64.
#ifndef RANDOMX_DATASET_EXTRA_SIZE
#define RANDOMX_DATASET_EXTRA_SIZE 33554368
#endif

//Number of instructions in a RandomX program. Must be divisible by 8.
#ifndef RANDOMX_PROGRAM_SIZE_V1
#define RANDOMX_PROGRAM_SIZE_V1    256
#endif
#ifndef RANDOMX_PROGRAM_SIZE_V2
#define RANDOMX_PROGRAM_SIZE_V2    384
#endif

#ifndef RANDOMX_PROGRAM_MAX_SIZE
#define RANDOMX_PROGRAM_MAX_SIZE   384
#endif

//Number of iterations during VM execution.
#ifndef RANDOMX_PROGRAM_ITERATIONS
#define RANDOMX_PROGRAM_ITERATIONS 2048
#endif

//Number of chained VM executions per hash.
#ifndef RANDOMX_PROGRAM_COUNT
#define RANDOMX_PROGRAM_COUNT      8
#endif

//Scratchpad L3 size in bytes. Must be a power of 2.
#ifndef RANDOMX_SCRATCHPAD_L3
#define RANDOMX_SCRATCHPAD_L3      2097152
#endif

//Scratchpad L2 size in bytes. Must be a power of two and less than or equal to RANDOMX_SCRATCHPAD_L3.
#ifndef RANDOMX_SCRATCHPAD_L2
#define RANDOMX_SCRATCHPAD_L2      262144
#endif

//Scratchpad L1 size in bytes. Must be a power of two (minimum 64) and less than or equal to RANDOMX_SCRATCHPAD_L2.
#ifndef RANDOMX_SCRATCHPAD_L1
#define RANDOMX_SCRATCHPAD_L1      16384
#endif

//Jump condition mask size in bits.
#ifndef RANDOMX_JUMP_BITS
#define RANDOMX_JUMP_BITS          8
#endif

//Jump condition mask offset in bits. The sum of RANDOMX_JUMP_BITS and RANDOMX_JUMP_OFFSET must not exceed 16.
#ifndef RANDOMX_JUMP_OFFSET
#define RANDOMX_JUMP_OFFSET        8
#endif

/*
Instruction frequencies (per 256 opcodes)
Total sum of frequencies must be 256
*/

//Integer instructions
#ifndef RANDOMX_FREQ_IADD_RS
#define RANDOMX_FREQ_IADD_RS       16
#endif
#ifndef RANDOMX_FREQ_IADD_M
#define RANDOMX_FREQ_IADD_M         7
#endif
#ifndef RANDOMX_FREQ_ISUB_R
#define RANDOMX_FREQ_ISUB_R        16
#endif
#ifndef RANDOMX_FREQ_ISUB_M
#define RANDOMX_FREQ_ISUB_M         7
#endif
#ifndef RANDOMX_FREQ_IMUL_R
#define RANDOMX_FREQ_IMUL_R        16
#endif
#ifndef RANDOMX_FREQ_IMUL_M
#define RANDOMX_FREQ_IMUL_M         4
#endif
#ifndef RANDOMX_FREQ_IMULH_R
#define RANDOMX_FREQ_IMULH_R        4
#endif
#ifndef RANDOMX_FREQ_IMULH_M
#define RANDOMX_FREQ_IMULH_M        1
#endif
#ifndef RANDOMX_FREQ_ISMULH_R
#define RANDOMX_FREQ_ISMULH_R       4
#endif
#ifndef RANDOMX_FREQ_ISMULH_M
#define RANDOMX_FREQ_ISMULH_M       1
#endif
#ifndef RANDOMX_FREQ_IMUL_RCP
#define RANDOMX_FREQ_IMUL_RCP       8
#endif
#ifndef RANDOMX_FREQ_INEG_R
#define RANDOMX_FREQ_INEG_R         2
#endif
#ifndef RANDOMX_FREQ_IXOR_R
#define RANDOMX_FREQ_IXOR_R        15
#endif
#ifndef RANDOMX_FREQ_IXOR_M
#define RANDOMX_FREQ_IXOR_M         5
#endif
#ifndef RANDOMX_FREQ_IROR_R
#define RANDOMX_FREQ_IROR_R         8
#endif
#ifndef RANDOMX_FREQ_IROL_R
#define RANDOMX_FREQ_IROL_R         2
#endif
#ifndef RANDOMX_FREQ_ISWAP_R
#define RANDOMX_FREQ_ISWAP_R        4
#endif

//Floating point instructions
#ifndef RANDOMX_FREQ_FSWAP_R
#define RANDOMX_FREQ_FSWAP_R        4
#endif
#ifndef RANDOMX_FREQ_FADD_R
#define RANDOMX_FREQ_FADD_R        16
#endif
#ifndef RANDOMX_FREQ_FADD_M
#define RANDOMX_FREQ_FADD_M         5
#endif
#ifndef RANDOMX_FREQ_FSUB_R
#define RANDOMX_FREQ_FSUB_R        16
#endif
#ifndef RANDOMX_FREQ_FSUB_M
#define RANDOMX_FREQ_FSUB_M         5
#endif
#ifndef RANDOMX_FREQ_FSCAL_R
#define RANDOMX_FREQ_FSCAL_R        6
#endif
#ifndef RANDOMX_FREQ_FMUL_R
#define RANDOMX_FREQ_FMUL_R        32
#endif
#ifndef RANDOMX_FREQ_FDIV_M
#define RANDOMX_FREQ_FDIV_M         4
#endif
#ifndef RANDOMX_FREQ_FSQRT_R
#define RANDOMX_FREQ_FSQRT_R        6
#endif

//Control instructions
#ifndef RANDOMX_FREQ_CBRANCH
#define RANDOMX_FREQ_CBRANCH       25
#endif
#ifndef RANDOMX_FREQ_CFROUND
#define RANDOMX_FREQ_CFROUND        1
#endif

//Store instruction
#ifndef RANDOMX_FREQ_ISTORE
#define RANDOMX_FREQ_ISTORE        16
#endif

//No-op instruction
#ifndef RANDOMX_FREQ_NOP
#define RANDOMX_FREQ_NOP            0
#endif
/*                               ------
                                  256
*/
