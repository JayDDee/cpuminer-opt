/*
 * Copyright 2018-2021 CryptoGraphics
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version. See LICENSE for more details.
 */

#ifndef Verthash_INCLUDE_ONCE
#define Verthash_INCLUDE_ONCE

#include "tiny_sha3/sha3.h"
#include "fopen_utf8.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Verthash constants used to compute bitmask, used inside kernel during IO pass
#define VH_HASH_OUT_SIZE 32
#define VH_BYTE_ALIGNMENT 16
#define VH_HEADER_SIZE 80

//-----------------------------------------------------------------------------
// Verthash data
//! Verthash C api for data maniputation.
typedef struct VerthashInfo
{
    char* fileName;
    uint8_t* data;
    uint64_t dataSize;
    uint32_t bitmask;
} verthash_info_t;

//! Must be called before usage. Reset all fields and set a mining data file name.
//! Error codes
//! 0 - Success(No error).
//! 1 - File name is invalid.
//! 2 - Memory allocation error
int verthash_info_init(verthash_info_t* info, const char* file_name);

//! Reset all fields and free allocated data.
void verthash_info_free(verthash_info_t* info);

//! Generate verthash data file and save it to specified location.
int verthash_generate_data_file(const char* output_file_name);

void verthash_hash( const void *blob_bytes, const size_t blob_size,
                    const void *input, void *output );

void verthash_sha3_512_prehash_72( const void *input );
void verthash_sha3_512_final_8( void *hash, const uint64_t nonce );

#endif // !Verthash_INCLUDE_ONCE

