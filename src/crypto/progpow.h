// Copyright (c) 2021 Andrea Lanfranchi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once
#ifndef FIRO_PROGPOW_H
#define FIRO_PROGPOW_H

#include <crypto/progpow/include/ethash/ethash.h>
#include <crypto/progpow/include/ethash/progpow.hpp>
#include <uint256.h>

class uint256;
class CBlockHeader;

/* Performs a full progpow hash (DAG loops implied) provided header already hash nHeight valued */
uint256 progpow_hash_full(const CBlockHeader& header, uint256& mix_hash);

/* Performs a light progpow hash (DAG loops excluded) provided header has mix_hash */
uint256 progpow_hash_light(const CBlockHeader& header);

#endif // FIRO_PROGPOW_H
