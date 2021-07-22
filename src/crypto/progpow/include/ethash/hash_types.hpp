// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#pragma once
#ifndef CRYPTO_PROGPOW_HASH_TYPES_HPP_
#define CRYPTO_PROGPOW_HASH_TYPES_HPP_

#include <crypto/progpow/include/ethash/hash_types.h>

namespace ethash
{
using hash256 = ethash_hash256;
using hash512 = ethash_hash512;
using hash1024 = ethash_hash1024;
using hash2048 = ethash_hash2048;
}  // namespace ethash

#endif // !CRYPTO_PROGPOW_HASH_TYPES_HPP_