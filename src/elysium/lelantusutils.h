// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_ELYSIUM_LELANTUSUTILS_H
#define FIRO_ELYSIUM_LELANTUSUTILS_H

#include "../base58.h"
#include "../uint256.h"

#include <fstream>

namespace elysium {

uint256 PrepareSpendMetadata(CBitcoinAddress const &receiver, CAmount referenceAmount);

std::vector<unsigned char> GetAESKey(const secp_primitives::GroupElement& pubcoin);

bool EncryptMintAmount(uint64_t amount, const secp_primitives::GroupElement& pubcoin, EncryptedValue ciphertext);

bool DecryptMintAmount(const EncryptedValue& encryptedValue, const secp_primitives::GroupElement& pubcoin, uint64_t& amount);

} // namespace elysium

#endif // FIRO_ELYSIUM_LELANTUSUTILS_H
