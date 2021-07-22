// Copyright (c) 2020 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../liblelantus/lelantus_primitives.h"

#include "lelantusprimitives.h"
#include "wallet.h"

namespace elysium {

uint160 GetSerialId(const secp_primitives::Scalar &serial)
{
	CDataStream ss(SER_GETHASH, 0);
	ss << serial;
	return Hash160(ss.begin(), ss.end());
}

MintEntryId::MintEntryId()
{
    SetNull();
}

MintEntryId::MintEntryId(lelantus::PrivateCoin const &coin, uint160 const &seedId)
    : MintEntryId(coin.getSerialNumber(), coin.getRandomness(), seedId)
{
}

MintEntryId::MintEntryId(secp_primitives::Scalar const &serial, secp_primitives::Scalar const &randomness, uint160 const &seedId)
{
    auto params = lelantus::Params::get_elysium();
    auto pubcoin = lelantus::LelantusPrimitives::commit(
        params->get_g(), serial, params->get_h0(), randomness);

    auto hashPub = primitives::GetPubCoinValueHash(pubcoin);
    CDataStream ss(SER_GETHASH, CLIENT_VERSION);
    ss << hashPub;
    ss << seedId;

    *this = MintEntryId(Hash(ss.begin(), ss.end()));
}

MintEntryId::MintEntryId(uint256 const &tag) : uint256(tag)
{
}

LelantusPrivateKey::LelantusPrivateKey(
    lelantus::Params const *_params,
    secp_primitives::Scalar const &_serial,
    secp_primitives::Scalar const &_randomness,
    ECDSAPrivateKey const &_ecdsaPrivateKey
    ) : params(_params), serial(_serial), randomness(_randomness), ecdsaPrivateKey(_ecdsaPrivateKey)
{
}

lelantus::PrivateCoin LelantusPrivateKey::GetPrivateCoin(LelantusAmount amount) const
{
    return lelantus::PrivateCoin(
        params,
        serial,
        amount,
        randomness,
        std::vector<unsigned char>(ecdsaPrivateKey.begin(), ecdsaPrivateKey.end()),
        LELANTUS_TX_VERSION_4);
}

SpendableCoin::SpendableCoin(LelantusPrivateKey const &_privateKey, LelantusAmount _amount, MintEntryId const &_id)
    : privateKey(_privateKey), amount(_amount), id(_id)
{
}

JoinSplitMint::JoinSplitMint()
{
    std::fill(encryptedValue, encryptedValue + sizeof(encryptedValue), 0);
}

JoinSplitMint::JoinSplitMint(MintEntryId _id, lelantus::PublicCoin const &_publicCoin, EncryptedValue const &_encryptedValue)
    : id(_id),
    publicCoin(_publicCoin)
{
    std::copy(_encryptedValue, _encryptedValue + sizeof(_encryptedValue), encryptedValue);
}

lelantus::JoinSplit CreateJoinSplit(
    std::vector<std::pair<lelantus::PrivateCoin, uint32_t>> const &coins,
    std::map<uint32_t, std::vector<lelantus::PublicCoin>> const &anonss,
    std::vector<std::vector<unsigned char>> anonymitySetHashes,
    LelantusAmount amount,
    std::vector<lelantus::PrivateCoin> const &coinOuts,
    std::map<uint32_t, uint256> const &groupBlockHashs,
    uint256 const &metaData)
{
    auto params = lelantus::Params::get_elysium();

    // int64_t is the max amount allowed for Elysium Lelantus transactions.
    if (amount > INT64_MAX) {
        throw std::runtime_error("spend amount would violate consensus limits");
    }

    // 4966 is the fixed size part of the transaction. It includes:
    // + 1 Lelantus input
    // + 1 Lelantus joinmint output
    // + 1 reference output
    // + the Elysium metadata
    // + the Elysium Lelantus outputs
    //
    // Then for every Elysium Lelantus input, there is an additional 2560 bytes of data.
    return {params, coins, anonss, anonymitySetHashes, amount, coinOuts, (uint64_t)payTxFee.GetFee(4966 + coins.size() * 2560), groupBlockHashs, metaData, LELANTUS_TX_VERSION_4_5};
}

} // namespace elysium