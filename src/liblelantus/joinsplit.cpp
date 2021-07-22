#include <chainparams.h>
#include "joinsplit.h"
#include "lelantus_prover.h"
#include "lelantus_verifier.h"
#include "../sigma/openssl_context.h"
#include "hash.h"
#include "util.h"

namespace lelantus {

JoinSplit::JoinSplit(const Params *p,
             const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,
             const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
             const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
             const Scalar& Vout,
             const std::vector<PrivateCoin>& Cout,
             uint64_t fee,
             const std::map<uint32_t, uint256>& groupBlockHashes,
             const uint256& txHash,
             unsigned int nVersion)
        :
        params (p),
        fee (fee),
        version (nVersion) {

    serialNumbers.reserve(Cin.size());
    for(size_t i = 0; i < Cin.size(); i++) {
        serialNumbers.emplace_back(Cin[i].first.getSerialNumber());
    }

    if (!HasValidSerials()) {
        throw std::invalid_argument("JoinSplit has invalid serial number");
    }

    std::vector <size_t> indexes;
    for(size_t i = 0; i < Cin.size(); i++) {
        size_t index;
        const auto& set = anonymity_sets.find(Cin[i].second);
        if(set == anonymity_sets.end())
            throw std::invalid_argument("No such anonymity set");

        if(!getIndex(Cin[i].first.getPublicCoin(), set->second, index))
            throw std::invalid_argument("No such coin in this anonymity set");

        groupIds.push_back(Cin[i].second);
        indexes.emplace_back(index);
    }

    coinNum = Cin.size();

    // generate public keys here, as we need it for challenge generation starting from LELANTUS_TX_VERSION_4_5
    generatePubKeys(Cin);

    LelantusProver prover(p, version);
    prover.proof(anonymity_sets, anonymity_set_hashes, uint64_t(0), Cin, indexes, ecdsaPubkeys, Vout, Cout, fee, lelantusProof, qkSchnorrProof);

    if(groupBlockHashes.size() != anonymity_sets.size())
        throw std::invalid_argument("Mismatch blockHashes and anonymity sets sizes.");

    SpendMetaData m(groupBlockHashes, txHash);

    signMetaData(Cin, m, Cout.size());

    coinGroupIdAndBlockHash = m.coinGroupIdAndBlockHash;
}

void JoinSplit::generatePubKeys(const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin) {
    ecdsaPubkeys.resize(Cin.size());
    for(size_t i = 0; i < Cin.size(); i++) {
        // Sign each spend under the public key associate with the serial number.
        secp256k1_pubkey pubkey;
        size_t pubkeyLen = 33;

        ecdsaPubkeys[i].resize(pubkeyLen);
        // TODO timing channel, since secp256k1_ec_pubkey_serialize does not expect its output to be secret.
        // See main_impl.h of ecdh module on secp256k1
        if (!secp256k1_ec_pubkey_create(
                OpenSSLContext::get_context(), &pubkey, Cin[i].first.getEcdsaSeckey())) {
            throw std::invalid_argument("Invalid secret key");
        }
        if (1 != secp256k1_ec_pubkey_serialize(
                OpenSSLContext::get_context(),
                &this->ecdsaPubkeys[i][0], &pubkeyLen, &pubkey, SECP256K1_EC_COMPRESSED)) {
            throw std::invalid_argument("Unable to serialize public key");
        }
    }
}

void JoinSplit::signMetaData(const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin, const SpendMetaData& m, size_t coutSize) {
    // Proves that the coin is correct w.r.t. serial number and hidden coin secret
    // (This proof is bound to the coin 'metadata', i.e., transaction hash)
    uint256 metahash = signatureHash(m, coutSize);


    ecdsaSignatures.resize(Cin.size());
    for(size_t i = 0; i < Cin.size(); i++) {
        // Sign each spend under the public key associate with the serial number.
        secp256k1_ecdsa_signature sig;
        ecdsaSignatures[i].resize(64);
        if (1 != secp256k1_ecdsa_sign(
                OpenSSLContext::get_context(), &sig,
                metahash.begin(), Cin[i].first.getEcdsaSeckey(), NULL, NULL)) {
            throw std::invalid_argument("Unable to sign with EcdsaSeckey.");
        }
        if (1 != secp256k1_ecdsa_signature_serialize_compact(
                OpenSSLContext::get_context(), &this->ecdsaSignatures[i][0], &sig)) {
            throw std::invalid_argument("Unable to serialize ecdsa_signature.");
        }
    }
}

bool JoinSplit::Verify(
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
        const std::vector<PublicCoin>& Cout,
        uint64_t Vout,
        const uint256& txHash) const {
    Scalar challenge;
    bool fSkipVerification = false;
    return Verify(anonymity_sets, anonymity_set_hashes, Cout, Vout, txHash, challenge, fSkipVerification);
}

#ifdef ENABLE_ELYSIUM
bool JoinSplit::VerifyElysium(
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
        const std::vector<PublicCoin>& Cout,
        uint64_t Vout,
        const uint256& txHash) const {
    Scalar challenge;
    bool fSkipVerification = false;
    return Verify(anonymity_sets, anonymity_set_hashes, Cout, Vout, txHash, challenge, fSkipVerification, INT64_MAX);
}
#endif

bool JoinSplit::Verify(
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<std::vector<unsigned char>>& anonymity_set_hashes,
        const std::vector<PublicCoin>& Cout,
        uint64_t Vout,
        const uint256& txHash,
        Scalar& challenge,
        bool fSkipVerification,
        boost::optional<int64_t> nMaxValueLelantusSpendPerTransaction) const {
    std::map<uint32_t, uint256> groupBlockHashes;

    for(const auto& idAndHash : coinGroupIdAndBlockHash) {
        groupBlockHashes[idAndHash.first] = idAndHash.second;
    }


    SpendMetaData m(groupBlockHashes, txHash);

    uint256 metahash = signatureHash(m, Cout.size());

    if(serialNumbers.size() != ecdsaSignatures.size() || serialNumbers.size() != ecdsaPubkeys.size()) {
        LogPrintf("Sigma spend failed due to serialNumbers and ecdsaSignatures/ecdsaPubkeys number mismatch.");
        return false;
    }

    for(size_t i = 0; i < serialNumbers.size(); i++) {
        // Verify ecdsa_signature, to make sure someone did not change the output of transaction.
        // Check sizes
        if (this->ecdsaPubkeys[i].size() != 33 || this->ecdsaSignatures[i].size() != 64) {
            LogPrintf("Lelantus joinsplit failed due to incorrect size of ecdsaSignature.");
            return false;
        }

        // Verify signature
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature signature;

        if (!secp256k1_ec_pubkey_parse(OpenSSLContext::get_context(), &pubkey, ecdsaPubkeys[i].data(), 33)) {
            LogPrintf("Lelantus joinsplit failed due to unable to parse ecdsaPubkey.");
            return false;
        }

        // Recompute and compare hash of public key
        Scalar coinSerialNumberExpected = PrivateCoin::serialNumberFromSerializedPublicKey(OpenSSLContext::get_context(), &pubkey);
        if (serialNumbers[i] != coinSerialNumberExpected) {
            LogPrintf("Lelantus joinsplit failed due to serial number does not match public key hash.");
            return false;
        }

        if (1 != secp256k1_ecdsa_signature_parse_compact(OpenSSLContext::get_context(), &signature, ecdsaSignatures[i].data()) ) {
            LogPrintf("Lelantus joinsplit failed due to signature cannot be parsed.");
            return false;
        }

        if (!secp256k1_ecdsa_verify(
                OpenSSLContext::get_context(), &signature, metahash.begin(), &pubkey)) {
            LogPrintf("Lelantus joinsplit failed due to signature cannot be verified.");
            return false;
        }
    }

    // Now verify lelantus proof
    LelantusVerifier verifier(params, version);
    return verifier.verify(anonymity_sets, anonymity_set_hashes, serialNumbers, ecdsaPubkeys, groupIds, uint64_t(0),Vout, fee, Cout, lelantusProof, qkSchnorrProof, challenge, fSkipVerification, nMaxValueLelantusSpendPerTransaction);
}


uint256 JoinSplit::signatureHash(const SpendMetaData& m, size_t coutSize) const {
    CHashWriter h(0,0);
    h << m << lelantusProof;
    return h.GetHash();
}

const std::vector<uint32_t>& JoinSplit::getCoinGroupIds() {
    return this->groupIds;
}

const std::vector<std::pair<uint32_t, uint256>>& JoinSplit::getIdAndBlockHashes() {
    return this->coinGroupIdAndBlockHash;
}

const std::vector<Scalar>& JoinSplit::getCoinSerialNumbers() {
    return this->serialNumbers;
}

const LelantusProof& JoinSplit::getLelantusProof() {
    return this->lelantusProof;
}

uint64_t JoinSplit::getFee() {
    return this->fee;
}

bool JoinSplit::getIndex(const PublicCoin& coin, const std::vector<PublicCoin>& anonymity_set, size_t& index) {
    for (std::size_t j = 0; j < anonymity_set.size(); ++j) {
        if(anonymity_set[j] == coin){
            index = j;
            return true;
        }
    }
    return false;
}

bool JoinSplit::HasValidSerials() const {
    for(size_t i = 0; i < serialNumbers.size(); i++)
        if(!serialNumbers[i].isMember() || serialNumbers[i].isZero())
            return false;
    return true;
}

bool JoinSplit::isSigmaToLelantus() const {
    return version == SIGMA_TO_LELANTUS_JOINSPLIT || version == SIGMA_TO_LELANTUS_JOINSPLIT_FIXED;
}

} //namespace lelantus