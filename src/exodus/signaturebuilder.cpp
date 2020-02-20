// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../libzerocoin/Zerocoin.h"
#include "../sigma/openssl_context.h"

#include "base58.h"

#include <secp256k1/include/Scalar.h>

#include "convert.h"
#include "coinsigner.h"
#include "sigmaprimitives.h"
#include "signaturebuilder.h"

namespace exodus {

SigmaV1SignatureBuilder::SigmaV1SignatureBuilder(
    CBitcoinAddress const &receiver,
    int64_t referenceAmount,
    SigmaProof const &proof,
    ECDSAPublicKey const &publicKey)
        : hasher(CHashWriter(SER_GETHASH, PROTOCOL_VERSION)), publicKey(publicKey)
{
    // serialize payload
    CKeyID keyId;
    if (!receiver.GetKeyID(keyId)) {
        throw std::runtime_error("Fail to get address key id.");
    }

    hasher.write(reinterpret_cast<char*>(keyId.begin()), keyId.size());

    // reference amount
    exodus::swapByteOrder(referenceAmount);
    hasher.write(reinterpret_cast<char*>(&referenceAmount), sizeof(referenceAmount));

    // serial and proof
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof.serial;
    serialized << proof.proof;
    std::vector<char> serializedData;
    serializedData.insert(serializedData.end(), serialized.begin(), serialized.end());

    hasher.write(serializedData.data(), serializedData.size());
}

ECDSASignature SigmaV1SignatureBuilder::Sign(CoinSigner &signer)
{
    auto hash = hasher.GetHash();
    return signer.Sign(hash.begin(), hash.end());
}

bool SigmaV1SignatureBuilder::Verify(ECDSASignature const &signature)
{
    auto hash = hasher.GetHash();

    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature parsedSignature;

    if (1 != secp256k1_ec_pubkey_parse(
        OpenSSLContext::get_context(),
        &pubkey,
        this->publicKey.data(),
        this->publicKey.size())) {
        throw std::runtime_error("Sigma spend failed due to unable to parse public key");
    }

    if (1 != secp256k1_ecdsa_signature_parse_compact(
        OpenSSLContext::get_context(),
        &parsedSignature,
        signature.data())) {
        throw std::runtime_error("Sigma spend fail due to unable to parse signature");
    }

    return 1 == secp256k1_ecdsa_verify(OpenSSLContext::get_context(), &parsedSignature, hash.begin(), &pubkey);
}

}