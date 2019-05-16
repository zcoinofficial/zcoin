#include "remint.h"
#include "zerocoin.h"
#include "libzerocoin/Commitment.h"

namespace sigma {

CoinRemintToV3::CoinRemintToV3(const libzerocoin::PrivateCoin &source) {
    coinRemintVersion = 1;
    coinMintVersion = source.getVersion();
    coinDenomination = (int)source.getPublicCoin().getDenomination();
    coinSerial = source.getSerialNumber();
    coinRandomness = source.getRandomness();
    coinPublicValue = source.getPublicCoin().getValue();

    if (coinMintVersion > ZEROCOIN_TX_VERSION_1) {
        if (coinSerial.bitSize() > 160)
            throw ZerocoinException("Invalid zerocoin mint");

        const unsigned char *secKey = source.getEcdsaSeckey();
        ecdsaPrivateKey = std::vector<unsigned char>(secKey, secKey+32);

        secp256k1_pubkey pubkey;

		if (!secp256k1_ec_pubkey_create(libzerocoin::ctx, &pubkey, secKey))
			throw ZerocoinException("Invalid secret key");

        size_t len = 33;
        ecdsaPublicKey = std::vector<unsigned char>(len, 0);
        secp256k1_ec_pubkey_serialize(libzerocoin::ctx, ecdsaPublicKey.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED);
    }
}

void CoinRemintToV3::SignTransaction(const libzerocoin::SpendMetaData &metadata) {
    if (ecdsaPrivateKey.empty())
        throw ZerocoinException("Invalid remint transaction");

    secp256k1_ecdsa_signature sig;
    uint256 metahash = GetMetadataHash(metadata);
	
    if (secp256k1_ecdsa_sign(libzerocoin::ctx, &sig, metahash.begin(), ecdsaPrivateKey.data(), NULL, NULL) != 1)
        throw ZerocoinException("Cannot sign remint transaction");

    ecdsaSignature = vector<unsigned char>(64, 0);
    secp256k1_ecdsa_signature_serialize_compact(libzerocoin::ctx, ecdsaSignature.data(), &sig);
}

Bignum CoinRemintToV3::CalculatePublicValue() const {
    // Parameters of coin committment group are always the same, we can take it from ZCParamsV2
    const libzerocoin::IntegerGroupParams &commGroup = ZCParamsV2->coinCommitmentGroup;
    // calculate g^serial * h^randomness (mod modulus)
    return (commGroup.g.pow_mod(coinSerial, commGroup.modulus).mul_mod(commGroup.h.pow_mod(coinRandomness, commGroup.modulus), commGroup.modulus));
}


uint256 CoinRemintToV3::GetMetadataHash(const libzerocoin::SpendMetaData &metadata) const {
    CHashWriter h(0,0);
	h << metadata << coinSerial << coinPublicValue;
    return h.GetHash();
}

bool CoinRemintToV3::Verify(const libzerocoin::SpendMetaData &metadata) const {
    // check integer constants to be within allowed ranges

    if (coinMintVersion != ZEROCOIN_TX_VERSION_1 && coinMintVersion != ZEROCOIN_TX_VERSION_2)
        return false;

    switch (coinDenomination) {
    case (int)libzerocoin::ZQ_LOVELACE:
    case (int)libzerocoin::ZQ_GOLDWASSER:
    case (int)libzerocoin::ZQ_RACKOFF:
    case (int)libzerocoin::ZQ_PEDERSEN:
    case (int)libzerocoin::ZQ_WILLIAMSON:
        if (!libzerocoin::PublicCoin(ZCParamsV2, coinPublicValue, (libzerocoin::CoinDenomination)coinDenomination).validate())
            return false;
        break;

    default:
        // wrong denomination
        return false;
    }

    if (coinSerial <= 0 || coinSerial >= ZCParamsV2->coinCommitmentGroup.groupOrder || coinRandomness <= 0 || coinRandomness >= ZCParamsV2->coinCommitmentGroup.groupOrder)
        return false;

    if (coinMintVersion == ZEROCOIN_TX_VERSION_2) {
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature signature;

        if (ecdsaPublicKey.size() != 33 || ecdsaSignature.size() != 64)
            return false;

        if (!secp256k1_ec_pubkey_parse(libzerocoin::ctx, &pubkey, ecdsaPublicKey.data(), 33))
            return false;

        if (coinSerial != libzerocoin::PrivateCoin::serialNumberFromSerializedPublicKey(libzerocoin::ctx, &pubkey))
            return false;

        uint256 metahash = GetMetadataHash(metadata);
        secp256k1_ecdsa_signature_parse_compact(libzerocoin::ctx, &signature, ecdsaSignature.data());
        if (!secp256k1_ecdsa_verify(libzerocoin::ctx, &signature, metahash.begin(), &pubkey))
            return false;
    }

    return true;
}

} // namespace sigma