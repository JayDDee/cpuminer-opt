#pragma once

#include <cstdint>
//#include <streams/hash/hash_interface.h>
#include "hash_interface.h"

namespace sha3 {

using BitSequence = hash::BitSequence;
using DataLength = hash::DataLength;

struct sha3_interface : hash::hash_interface {};

} // namespace sha3
