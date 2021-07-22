// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../crypto/aes.h"
#include "../crypto/hmac_sha512.h"
#include "../wallet/wallet.h"

#include "lelantusprimitives.h"
#include "lelantusutils.h"

namespace elysium {

uint256 PrepareSpendMetadata(
    CBitcoinAddress const &receiver,
    CAmount referenceAmount)
{
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);

    // serialize payload
    uint160 keyId;
    AddressType type;
    if (!receiver.GetIndexKey(keyId, type)) {
        throw std::invalid_argument("Fail to get address key id.");
    }

    hasher.write(reinterpret_cast<char*>(keyId.begin()), keyId.size());

    referenceAmount = htole64(referenceAmount);
    hasher.write(reinterpret_cast<char*>(&referenceAmount), sizeof(referenceAmount));

    return hasher.GetHash();
}

std::vector<unsigned char> GetAESKey(const secp_primitives::GroupElement& pubcoin) {
    uint32_t keyPath = primitives::GetPubCoinValueHash(pubcoin).GetFirstUint32();
    CKey secret;
    {
        pwalletMain->GetKeyFromKeypath(BIP44_ELYSIUM_LELANTUSMINT_VALUE_INDEX, keyPath, secret);
    }

    std::vector<unsigned char> result(CHMAC_SHA512::OUTPUT_SIZE);

    CHMAC_SHA512(secret.begin(), secret.size()).Finalize(&result[0]);
    return result;
}

bool EncryptMintAmount(uint64_t amount, const secp_primitives::GroupElement& pubcoin, EncryptedValue ciphertext) {
    LOCK(pwalletMain->cs_wallet);
    std::vector<unsigned char> key = GetAESKey(pubcoin);

    AES256Encrypt enc(key.data());
    std::array<uint8_t, 16> plaintext;

    memcpy(plaintext.data(), &amount, 8);
    enc.Encrypt(&ciphertext[0], plaintext.data());

    return true;
}

bool DecryptMintAmount(const EncryptedValue& encryptedValue, const secp_primitives::GroupElement& pubcoin, uint64_t& amount) {
    if(pwalletMain->IsLocked()) {
        amount = 0;
        return false;
    }

    LOCK(pwalletMain->cs_wallet);
    std::vector<unsigned char> key = GetAESKey(pubcoin);

    AES256Decrypt dec(key.data());
    std::vector<unsigned char> plaintext(16);
    dec.Decrypt(plaintext.data(), &encryptedValue[0]);

    memcpy(&amount, plaintext.data(), 8);
    return true;
}

} // namespace elysium