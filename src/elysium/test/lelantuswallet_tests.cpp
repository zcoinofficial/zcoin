// Copyright (c) 2020 The Zcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../../lelantus.h"
#include "../../test/fixtures.h"

#include "../lelantusdb.h"
#include "../lelantuswallet.h"

#include "validation.h"

#include <boost/test/unit_test.hpp>

using namespace elysium;

class TestLelantusWallet : public LelantusWallet
{
public:
    TestLelantusWallet() : LelantusWallet(new LelantusWallet::Database)
    {
    }

public:
    MintPool& GetMintPool()
    {
        return mintPool;
    }

    uint32_t GetSeedIndex(CKeyID const &seedId/*, uint32_t &change*/)
    {
        uint32_t change;
        return LelantusWallet::GetSeedIndex(seedId, change);
    }
};

struct LelantusWalletTestingSetup : LelantusTestingSetup
{
    std::unique_ptr<TestLelantusWallet> wallet;

    LelantusWalletTestingSetup() : wallet(new TestLelantusWallet)
    {
        lelantusDb = new LelantusDb(pathTemp / "elysium_lelantus_tests", true);
        wallet->ReloadMasterKey();
    }
};

namespace lelantus {

BOOST_FIXTURE_TEST_SUITE(elysium_lelantuswallet_tests, LelantusWalletTestingSetup)

#define CHECK_EXPECTED_INDEX(e, r) BOOST_CHECK_EQUAL(e, wallet->GetSeedIndex(r.GetMintPoolEntry().seedId));

BOOST_AUTO_TEST_CASE(mint_reservation)
{
    auto &mintPool = wallet->GetMintPool();

    {
        // commit nothing
        auto recv1 = wallet->GenerateMint(3, 10 * COIN);
        CHECK_EXPECTED_INDEX(0, recv1);

        auto recv2 = wallet->GenerateMint(3, 20 * COIN);
        CHECK_EXPECTED_INDEX(1, recv2);

        BOOST_CHECK_EQUAL(20, mintPool.size());
    }
    BOOST_CHECK_EQUAL(22, mintPool.size());

    {
        // commit some coin
        auto recv1 = wallet->GenerateMint(3, 10 * COIN);
        CHECK_EXPECTED_INDEX(0, recv1);

        auto recv2 = wallet->GenerateMint(3, 20 * COIN);
        CHECK_EXPECTED_INDEX(1, recv2);

        BOOST_CHECK_EQUAL(20, mintPool.size());

        recv1.Commit();
    }
    BOOST_CHECK_EQUAL(21, mintPool.size());

    {
        // commit skip some index
        // commit some coin
        auto recv1 = wallet->GenerateMint(3, 10 * COIN);
        CHECK_EXPECTED_INDEX(1, recv1);

        auto recv2 = wallet->GenerateMint(3, 20 * COIN);
        CHECK_EXPECTED_INDEX(2, recv2);

        BOOST_CHECK_EQUAL(20, mintPool.size());

        recv2.Commit();
    }
    BOOST_CHECK_EQUAL(21, mintPool.size());

    {
        // next time should got index 1
        auto recv1 = wallet->GenerateMint(3, 10 * COIN);
        CHECK_EXPECTED_INDEX(1, recv1);

        recv1.Commit();
    }
    BOOST_CHECK_EQUAL(20, mintPool.size()); // should not be added back

    {
        // next time should get index 3 since index 2 is used
        auto recv1 = wallet->GenerateMint(3, 10 * COIN);
        CHECK_EXPECTED_INDEX(3, recv1);

        recv1.Commit();
    }
    BOOST_CHECK_EQUAL(20, mintPool.size()); // should not be added back again
}

#undef CHECK_EXPECTED_INDEX

BOOST_AUTO_TEST_CASE(joinsplit_building)
{
    constexpr PropertyId property = 3;
    constexpr size_t AllMints = 10;

    GenerateBlocks(110);

    std::vector<MintEntryId> ids;
    for (size_t i = 0; i != AllMints; i++) {
        auto r = wallet->GenerateMint(property, 100 * COIN);
        r.Commit();

        CDataStream  ss(SER_NETWORK, PROTOCOL_VERSION);
        lelantus::GenerateMintSchnorrProof(r.coin, ss);

        std::vector<unsigned char> data(ss.begin(), ss.end());
        lelantusDb->WriteMint(property, r.coin.getPublicCoin(), 100, r.id, 100 * COIN, data);

        ids.push_back(r.id);
    }
    lelantusDb->CommitCoins();

    for (size_t i = 0; i != AllMints; i++) {
        LelantusMintChainState chainState(100, 0, i);
        BOOST_CHECK_NO_THROW(wallet->UpdateMintChainstate(ids[i], chainState));
    }

    uint256 metaData = ArithToUint256(2);
    std::vector<SpendableCoin> spendables;
    boost::optional<LelantusWallet::MintReservation> mintReservation;
    LelantusAmount changeAmount;

    BOOST_CHECK_NO_THROW(wallet->CreateJoinSplit(
        property, 200 * COIN, metaData, spendables, mintReservation, changeAmount));
}

lelantus::JoinSplit CreateEvilJoinSplit(
        TestLelantusWallet& wallet,
        PropertyId property,
        CAmount amountToSpend,
        uint256 const &metadata,
        std::vector<SpendableCoin> &spendables,
        boost::optional<LelantusWallet::MintReservation> &changeMint,
        LelantusAmount &change)
{
    if (amountToSpend < 0) {
        throw std::invalid_argument("Amount to spend could not be negative");
    }

    std::map<uint32_t, std::vector<lelantus::PublicCoin>> anonss;
    std::vector<std::pair<lelantus::PrivateCoin, uint32_t>> coins;
    coins.reserve(spendables.size());

    for (auto const &s : spendables) {
        auto priv = s.privateKey.GetPrivateCoin(s.amount);
        auto group = lelantusDb->GetGroup(property, priv.getPublicCoin());

        anonss[group] = {};

        coins.emplace_back(priv, group);
    }

    uint256 highestBlock;
    int highestBlockHeight = 0;

    std::map<uint32_t, uint256> blockHashes;
    for (auto &anons : anonss) {
        int blockHeight = INT_MAX;
        anons.second = lelantusDb->GetAnonymityGroup(property, anons.first, SIZE_MAX, blockHeight);
        auto block = chainActive[blockHeight];
        if (!block) throw std::runtime_error("Failed to create joinsplit due to invalid anonymity group input");
        blockHashes[anons.first] = block->GetBlockHash();

        if (block->nHeight > highestBlockHeight) {
            highestBlockHeight = block->nHeight;
            highestBlock = block->GetBlockHash();
        }
    }

    // It is safe to use the hashes of blocks instead of the hashes of anonymity sets because blocks hashes are
    // necessarily dependent on anonymity set hashes.
    std::vector<std::vector<unsigned char>> anonymitySetHashes;
    std::vector<unsigned char> anonymitySetHash(highestBlock.begin(), highestBlock.end());
    anonymitySetHashes.push_back(anonymitySetHash);

    // reserve change
    std::vector<lelantus::PrivateCoin> coinOuts;
    if (change) {
        changeMint = wallet.GenerateMint(property, change);
    }

    std::vector<lelantus::PublicCoin> pubCoinOuts;
    if (changeMint.get_ptr() != nullptr) {
        coinOuts = {changeMint->coin};
        pubCoinOuts = {changeMint->coin.getPublicCoin()};
    }

    // It is safe to use blockHash instead of hashes of the anonymity sets because any change in the latter will
    // necessarily result in a change in the former.
    auto js = ::CreateJoinSplit(coins, anonss, anonymitySetHashes, amountToSpend, coinOuts, blockHashes, metadata);

    if (!js.VerifyElysium(anonss, anonymitySetHashes, pubCoinOuts, amountToSpend, metadata)) {
        throw std::runtime_error("Fail to verify created join/split object");
    }

    return js;
}

BOOST_AUTO_TEST_CASE(doublespend)
{
    constexpr PropertyId property = 3;

    GenerateBlocks(110);

    LelantusWallet::MintReservation mint = wallet->GenerateMint(property, 100 * COIN);
    mint.Commit();

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    lelantus::GenerateMintSchnorrProof(mint.coin, ss);

    std::vector<unsigned char> data(ss.begin(), ss.end());
    lelantusDb->WriteMint(property, mint.coin.getPublicCoin(), 100, mint.id, 100 * COIN, data);

    LelantusWallet::MintReservation mint2 = wallet->GenerateMint(property, COIN);
    mint2.Commit();

    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    lelantus::GenerateMintSchnorrProof(mint2.coin, ss2);

    std::vector<unsigned char> data2(ss2.begin(), ss2.end());
    lelantusDb->WriteMint(property, mint2.coin.getPublicCoin(), 100, mint2.id, COIN, data2);

    lelantusDb->CommitCoins();

    GenerateBlocks(2);

    LelantusMintChainState chainState(100, 0, 1);
    BOOST_CHECK_NO_THROW(wallet->UpdateMintChainstate(mint.id, chainState));

    uint256 metaData = ArithToUint256(2);
    boost::optional<LelantusWallet::MintReservation> mintReservation;
    LelantusAmount changeAmount;

    ECDSAPrivateKey ecdsaPrivateKey;
    memcpy((void *) mint.coin.getEcdsaSeckey(), ecdsaPrivateKey.begin(), 32);
    LelantusPrivateKey privateKey(mint.coin.getParams(), mint.coin.getSerialNumber(), mint.coin.getRandomness(), ecdsaPrivateKey);
    std::vector<SpendableCoin> spendables = {SpendableCoin(privateKey, COIN, mint.id)};

    lelantus::JoinSplit goodJoinSplit = wallet->CreateJoinSplit(property, 2 * COIN, metaData, spendables, mintReservation, changeAmount);
    lelantus::JoinSplit badJoinSplit = wallet->CreateJoinSplit(property, 3 * COIN, metaData, spendables, mintReservation, changeAmount);

    for (Scalar const& serial: goodJoinSplit.getCoinSerialNumbers()) {
        BOOST_CHECK_EQUAL(true, lelantusDb->WriteSerial(property, serial, 110, uint256()));
    }

    for (Scalar const& serial: badJoinSplit.getCoinSerialNumbers()) {
        BOOST_CHECK_EQUAL(false, lelantusDb->WriteSerial(property, serial, 110, uint256()));
    }
}

BOOST_AUTO_TEST_SUITE_END()

}; // namespace lelantus