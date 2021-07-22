#include "../convert.h"
#include "../lelantusdb.h"

#include "../../test/fixtures.h"
#include "../../test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

namespace elysium {

namespace {

class TestLelantusDb : public LelantusDb
{
public:
    static const size_t DEFAULT_GROUPSIZE = 65000;
    static const size_t DEFAULT_STARTCOINS = 16000;

public:
    TestLelantusDb(
        const boost::filesystem::path& path,
        bool wipe,
        size_t groupSize = DEFAULT_GROUPSIZE,
        size_t startCoins = DEFAULT_STARTCOINS)
        : LelantusDb(path, wipe, groupSize, startCoins)
    {
    }

// proxy
public:
    bool WriteGroupSize(uint64_t groupSize, uint64_t mintAmount)
    {
        return LelantusDb::WriteGroupSize(groupSize, mintAmount);
    }

    std::pair<uint64_t, uint64_t> ReadGroupSize()
    {
        return LelantusDb::ReadGroupSize();
    }

    int GetLastGroup(PropertyId id, uint64_t &coins)
    {
        return LelantusDb::GetLastGroup(id, coins);
    }

// debug
public:
    void DumpDB() {
#define HEX(x) HexStr(x.data(), x.data() + x.size())

        auto it = NewIterator();
        it->SeekToFirst();

        for (; it->Valid(); it->Next()) {
            auto k = it->key();
            auto v = it->value();
            std::cout << "x'" << k[0] << " " << HEX(k) << " " << HEX(v) << std::endl;
        }

#undef HEX
    }
};

class LelantusDbTestingSetup : public TestingSetup
{
public:
    LelantusDbTestingSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
    }

    std::unique_ptr<TestLelantusDb> CreateDb(
        const boost::filesystem::path& path,
        bool wipe,
        size_t groupSize = TestLelantusDb::DEFAULT_GROUPSIZE,
        size_t startCoins = TestLelantusDb::DEFAULT_STARTCOINS)
    {
        return std::unique_ptr<TestLelantusDb>(new TestLelantusDb(path, wipe, groupSize, startCoins));
    }
};

} // empty namespace

BOOST_FIXTURE_TEST_SUITE(elysium_lelantusdb_tests, LelantusDbTestingSetup)

BOOST_AUTO_TEST_CASE(scalars)
{
    auto db = CreateDb(GetDataDir() / "test_lelantusdb", true);

    uint256 spendTx;

#define HAS(id, s) BOOST_CHECK_MESSAGE(db->HasSerial(id, s, spendTx), \
    strprintf("Expect to have %s in group %d, but not found", secp_primitives::Scalar(s).GetHex(), id))

#define HAS_NO(id, s) BOOST_CHECK_MESSAGE(!db->HasSerial(id, s, spendTx), \
    strprintf("Expect to have no %s in group %d, but found", secp_primitives::Scalar(s).GetHex(), id))

    // have no serials before adding
    HAS_NO(2, 1);
    HAS_NO(3, 2);
    HAS_NO(3, 3);

    uint256 dummyTx = ArithToUint256(arith_uint256(100));

    // add some serials
    BOOST_CHECK(db->WriteSerial(2, 1, 10, dummyTx));
    BOOST_CHECK(db->WriteSerial(3, 2, 10, dummyTx));
    BOOST_CHECK(db->WriteSerial(3, 3, 10, dummyTx));

    // confirm serials are added
    HAS(2, 1);
    HAS(3, 2);
    HAS(3, 3);

    // confirm serials are not included
    HAS_NO(2, 2);
    HAS_NO(2, 3);
    HAS_NO(2, 4);

    // test spend tx
    uint256 tx1 = ArithToUint256(arith_uint256(101));
    uint256 tx2 = ArithToUint256(arith_uint256(102));

    // add some serials with unique spend txs
    BOOST_CHECK(db->WriteSerial(2, 3, 11, tx1));
    BOOST_CHECK(db->WriteSerial(2, 4, 11, tx2));

    // verify serials are added
    HAS(2, 3);
    HAS(2, 4);

    // verify spend tx are recorded correctly
    uint256 recordedTx;
    BOOST_CHECK(db->HasSerial(2, 3, recordedTx));
    BOOST_CHECK_MESSAGE(tx1 == recordedTx,
        strprintf("Expected spendTx %s, got %s", tx1.GetHex(), recordedTx.GetHex()));

    BOOST_CHECK(db->HasSerial(2, 4, recordedTx));
    BOOST_CHECK_MESSAGE(tx2 == recordedTx,
        strprintf("Expected spendTx %s, got %s", tx2.GetHex(), recordedTx.GetHex()));

    // try to add duplicated serial, should fail
    BOOST_CHECK_MESSAGE(!db->WriteSerial(2, 3, 12, tx1), "Success to write duplicated serial");

    // add one more should success
    BOOST_CHECK_MESSAGE(db->WriteSerial(4, 99, 12, tx1), "Fail to write serial");

    HAS(4, 99);

    // remove by block number
    db->DeleteAll(12);

    HAS_NO(4, 99);

    // verify serials in block before 12 are included
    HAS(2, 1);
    HAS(3, 2);
    HAS(3, 3);

    HAS(2, 3);
    HAS(2, 4);

    // remove to all
    db->DeleteAll(0);

    HAS_NO(2, 3);
    HAS_NO(2, 4);

    HAS_NO(2, 1);
    HAS_NO(3, 2);
    HAS_NO(3, 3);

#undef HAS
#undef HAS_NO
}

BOOST_AUTO_TEST_CASE(groupsize)
{
    auto db = CreateDb(GetDataDir() / "test_lelantusdb", true, 1000, 200);

    BOOST_CHECK_MESSAGE(!db->WriteGroupSize(500, 100), "Success to overwrite group size");

    std::pair<uint64_t, uint64_t> expected(1000, 200);
    BOOST_CHECK(db->ReadGroupSize() == expected);
}

BOOST_AUTO_TEST_CASE(sliding_windows)
{
    auto db = CreateDb(GetDataDir() / "test_lelantusdb", true, 100, 10);
    std::vector<lelantus::PublicCoin> addedCoins;

    auto addCoins = [&](PropertyId id, size_t coins, int block) {
        for (size_t i = 0; i != coins; i++) {
            secp_primitives::GroupElement g;
            g.randomize();

            uint256 tag;

            db->WriteMint(id, g, block, tag, 1, {});

            addedCoins.push_back(g);
        }
    };

    typedef std::vector<lelantus::PublicCoin>::const_iterator CoinItr;
    auto verifyGroup = [&](PropertyId id, int group, size_t count, CoinItr i, CoinItr j, std::string &result) {
        int block = INT_MAX;
        auto mints = db->GetAnonymityGroup(id, group, count, block);
        if (mints.size() != std::distance(i, j)) {
            result = strprintf("Check id %d, group %d, got %d but expect %d", id, group, mints.size(), std::distance(i, j));
            return;
        }

        auto it = mints.begin();
        for (; it != mints.end() && i != j; i++, it++) {
            if (*it != *i) {
                result = strprintf("Coin add possition %d are not equal", std::distance(mints.begin(), it));
                return;
            }
        }

        result = "";
    };

    auto verifyLastGroup = [&](PropertyId id, int group, uint64_t coins) {
        uint64_t actualCoins;
        auto actualGroup = db->GetLastGroup(id, actualCoins);

        BOOST_CHECK_MESSAGE(actualGroup == group, strprintf("Expect group %d, actual %d", group, actualGroup));
        BOOST_CHECK_MESSAGE(actualCoins == coins, strprintf("Expect coins %d, actual %d", coins, actualCoins));
    };

#define VERIFY_GROUP(id, group, count, i, j) \
{ \
    std::string result; \
    verifyGroup(id, group, count, i, j, result); \
    BOOST_CHECK_MESSAGE(result == "", result); \
}

    addCoins(1, 50, 10); // 50
    db->CommitCoins();
    verifyLastGroup(1, 0, 50);
    VERIFY_GROUP(1, 0, 10, addedCoins.begin(), addedCoins.begin() + 10);
    VERIFY_GROUP(1, 0, 50, addedCoins.begin(), addedCoins.begin() + 50);
    VERIFY_GROUP(1, 0, 900, addedCoins.begin(), addedCoins.begin() + 50);

    addCoins(1, 50, 11); // 50, 50
    db->CommitCoins();
    verifyLastGroup(1, 0, 100);
    VERIFY_GROUP(1, 0, 100, addedCoins.begin(), addedCoins.begin() + 100);

    addCoins(1, 1, 12); // 50, *50, 1
    db->CommitCoins();
    verifyLastGroup(1, 1, 51);
    VERIFY_GROUP(1, 1, 10, addedCoins.begin() + 50, addedCoins.begin() + 60);
    VERIFY_GROUP(1, 1, 51, addedCoins.begin() + 50, addedCoins.begin() + 101);

    addCoins(1, 20, 13); // 50, *50, 1, 20

    addCoins(1, 29, 13); // 50, *50, 1, (20 + 29)
    db->CommitCoins();
    verifyLastGroup(1, 1, 100);
    VERIFY_GROUP(1, 0, 10, addedCoins.begin(), addedCoins.begin() + 10);
    // VERIFY_GROUP(1, 0, 900, addedCoins.begin(), addedCoins.begin() + 50);
    VERIFY_GROUP(1, 1, 1000, addedCoins.begin() + 50, addedCoins.end());

    addCoins(1, 5, 14); // 50, *50, 1, *(20 + 29), 5
    db->CommitCoins();
    verifyLastGroup(1, 2, 54);

    addCoins(1, 26, 15); // 50, *50, 1, *(20 + 29), 5, 26
    db->CommitCoins();
    verifyLastGroup(1, 2, 80);

    addCoins(1, 15, 16); // 50, *50, 1, *(20 + 29), 5, 26, 15
    db->CommitCoins();
    verifyLastGroup(1, 2, 95);

    addCoins(1, 4, 17); // 50, *50, 1, *(20 + 29), 10, 26, 15, 4
    addCoins(1, 1, 17); // 50, *50, 1, *(20 + 29), 10, 26, 15, (4 + 1)
    addCoins(1, 1, 17); // 50, *50, 1, *(20 + 29), 10, 26, *15, (4 + 1 + 1)
    db->CommitCoins();
    verifyLastGroup(1, 3, 21);

    db->DeleteAll(17); // 50, *50, 1, *(20 + 29), 5, 26, 15
    verifyLastGroup(1, 2, 95);
    VERIFY_GROUP(1, 0, 10, addedCoins.begin(), addedCoins.begin() + 10);
    VERIFY_GROUP(1, 1, 10, addedCoins.begin() + 50, addedCoins.begin() + 60);
    VERIFY_GROUP(1, 2, 10, addedCoins.begin() + 101, addedCoins.begin() + 111);

    // remove many blocks
    db->DeleteAll(14); // 50, *50, 1, (20 + 29)
    verifyLastGroup(1, 1, 100);
    VERIFY_GROUP(1, 0, 10, addedCoins.begin(), addedCoins.begin() + 10);
    VERIFY_GROUP(1, 1, 1000, addedCoins.begin() + 50, addedCoins.begin() + 150);

    addedCoins.resize(150);

    // add some
    addCoins(1, 9, 14); // 50, *50, 1, *(20 + 29), 9
    db->CommitCoins();
    verifyLastGroup(1, 2, 58);
    VERIFY_GROUP(1, 0, 10, addedCoins.begin(), addedCoins.begin() + 10);
    VERIFY_GROUP(1, 2, 1000, addedCoins.begin() + 101, addedCoins.end());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace elysium