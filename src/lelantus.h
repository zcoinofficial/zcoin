#ifndef _MAIN_LELANTUS_H__
#define _MAIN_LELANTUS_H__

#include "amount.h"
#include "chain.h"
#include "liblelantus/coin.h"
#include "liblelantus/joinsplit.h"
#include "consensus/validation.h"
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include "liblelantus/params.h"
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include "coin_containers.h"

namespace lelantus_mintspend { class lelantus_mintspend_test; }

namespace lelantus {

// Lelantus transaction info, added to the CBlock to ensure zerocoin mint/spend transactions got their info stored into index
class CLelantusTxInfo {
public:
    // all the zerocoin transactions encountered so far
    std::set<uint256> zcTransactions;

    // Vector of <pubCoin, <amount, hash>> for all the mints.
    std::vector<std::pair<lelantus::PublicCoin, std::pair<uint64_t, uint256>>> mints;

    // serial for every spend (map from serial to coin group id)
    std::unordered_map<Scalar, int> spentSerials;

    // information about transactions in the block is complete
    bool fInfoIsComplete;

    CLelantusTxInfo(): fInfoIsComplete(false) {}

    // finalize everything
    void Complete();
};

bool IsLelantusAllowed();
bool IsLelantusAllowed(int height);

bool IsAvailableToMint(const CAmount& amount);

void GenerateMintSchnorrProof(const lelantus::PrivateCoin& coin, CDataStream&  serializedSchnorrProof);
bool VerifyMintSchnorrProof(const uint64_t& v, const secp_primitives::GroupElement& commit, const SchnorrProof& schnorrProof);
void ParseLelantusMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin,  SchnorrProof& schnorrProof, uint256& mintTag);
void ParseLelantusJMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin, std::vector<unsigned char>& encryptedValue);
void ParseLelantusJMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin, std::vector<unsigned char>& encryptedValue, uint256& mintTag);
void ParseLelantusMintScript(const CScript& script, secp_primitives::GroupElement& pubcoin);
std::unique_ptr<JoinSplit> ParseLelantusJoinSplit(const CTransaction& tx);

size_t GetSpendInputs(const CTransaction &tx, const CTxIn& in);
size_t GetSpendInputs(const CTransaction &tx);
CAmount GetSpendTransparentAmount(const CTransaction& tx);

bool CheckLelantusBlock(CValidationState &state, const CBlock& block);

bool CheckLelantusTransaction(
    const CTransaction &tx,
	CValidationState &state,
	uint256 hashTx,
	bool isVerifyDB,
	int nHeight,
	bool isCheckWallet,
	bool fStatefulSigmaCheck,
    sigma::CSigmaTxInfo* sigmaTxInfo,
	CLelantusTxInfo* lelantusTxInfo);

void DisconnectTipLelantus(CBlock &block, CBlockIndex *pindexDelete);

bool ConnectBlockLelantus(
  CValidationState& state,
  const CChainParams& chainparams,
  CBlockIndex* pindexNew,
  const CBlock *pblock,
  bool fJustCheck=false);

/*
 * Get COutPoint(txHash, index) from the chain using pubcoin value alone.
 */
bool GetOutPointFromBlock(COutPoint& outPoint, const GroupElement &pubCoinValue, const CBlock &block);
bool GetOutPoint(COutPoint& outPoint, const lelantus::PublicCoin &pubCoin);
bool GetOutPoint(COutPoint& outPoint, const GroupElement &pubCoinValue);
// This one gets outpoint from hash of full Lelantus commitment
bool GetOutPoint(COutPoint& outPoint, const uint256 &pubCoinValueHash);
// This one gets outpoint from hash of reduced Lelantus commitment
bool GetOutPointFromMintTag(COutPoint& outPoint, const uint256 &pubCoinTag);


bool BuildLelantusStateFromIndex(CChain *chain);

std::vector<Scalar> GetLelantusJoinSplitSerialNumbers(const CTransaction &tx, const CTxIn &txin);
std::vector<uint32_t> GetLelantusJoinSplitIds(const CTransaction &tx, const CTxIn &txin);

/*
 * Util functions
 */
size_t CountCoinInBlock(CBlockIndex const *index, int id);

class CLelantusMempoolState {
private:
    // serials of spends currently in the mempool mapped to tx hashes
    std::unordered_map<Scalar, uint256, sigma::CScalarHash> mempoolCoinSerials;
    // mints in the mempool
    std::unordered_set<GroupElement> mempoolMints;

public:
    // Check if there is a conflicting tx in the blockchain or mempool
    bool HasCoinSerial(const Scalar& coinSerial);

    bool HasMint(const GroupElement& pubCoin);

    // Add spend into the mempool.
    bool AddSpendToMempool(const Scalar &coinSerial, uint256 txHash);

    void AddMintToMempool(const GroupElement& pubCoins);
    void RemoveMintFromMempool(const GroupElement& pubCoin);

    // Get conflicting tx hash by coin serial number
    uint256 GetMempoolConflictingTxHash(const Scalar& coinSerial);

    // Remove spend from the mempool (usually as the result of adding tx to the block)
    void RemoveSpendFromMempool(const Scalar& coinSerial);

    std::unordered_map<Scalar, uint256, sigma::CScalarHash> const & GetMempoolCoinSerials() const { return mempoolCoinSerials; }

    void Reset();
};

/*
 * State of minted/spent coins as extracted from the index
 */
class CLelantusState {
friend bool BuildLelantusStateFromIndex(CChain *, std::set<CBlockIndex *> &);
public:
    // First and last block where mint with given id was seen
    struct LelantusCoinGroupInfo {
        LelantusCoinGroupInfo() : firstBlock(nullptr), lastBlock(nullptr), nCoins(0) {}

        // first and last blocks having coins with given id minted
        CBlockIndex *firstBlock;
        CBlockIndex *lastBlock;
        // total number of minted coins with such parameters
        int nCoins;
    };

public:
    CLelantusState(
        size_t maxCoinInGroup = ZC_LELANTUS_MAX_MINT_NUM,
        size_t startGroupSize = ZC_LELANTUS_SET_START_SIZE);

    // Add mints in block, automatically assigning id to it
    void AddMintsToStateAndBlockIndex(CBlockIndex *index, const CBlock* pblock);

    // Add serial to the list of used ones
    void AddSpend(const Scalar &serial, int coinGroupId);

    // Add everything from the block to the state
    void AddBlock(CBlockIndex *index);

    // Disconnect block from the chain rolling back mints and spends
    void RemoveBlock(CBlockIndex *index);

    // Query coin group with given id
    bool GetCoinGroupInfo(int group_id, LelantusCoinGroupInfo &result);

    // Query if the coin serial was previously used
    bool IsUsedCoinSerial(const Scalar& coinSerial);
        // Query if the hash of a coin serial was previously used. If so, store preimage in coinSerial param
    bool IsUsedCoinSerialHash(Scalar &coinSerial, const uint256 &coinSerialHash);

    // Query if there is a coin with given pubCoin value
    bool HasCoin(const lelantus::PublicCoin& pubCoin);
    // Query if there is a coin with given hash of a pubCoin value. If so, store preimage in pubCoin param
    bool HasCoinHash(GroupElement &pubCoinValue, const uint256 &pubCoinValueHash);
    // Query if there is a coin with given tag
    bool HasCoinTag(GroupElement &pubCoinValue, const uint256 &pubCoinTag);


    // Given id returns latest anonymity set and corresponding block hash
    // Do not take into account coins with height more than maxHeight
    // Returns number of coins satisfying conditions
    int GetCoinSetForSpend(
        CChain *chain,
        int maxHeight,
        int id,
        uint256& blockHash_out,
        std::vector<lelantus::PublicCoin>& coins_out,
        std::vector<unsigned char>& setHash_out);

    void GetAnonymitySet(
            int coinGroupID,
            bool fStartLelantusBlacklist,
            std::vector<lelantus::PublicCoin>& coins_out);

    // Return height of mint transaction and id of minted coin
    std::pair<int, int> GetMintedCoinHeightAndId(const lelantus::PublicCoin& pubCoin);

    // Reset to initial values
    void Reset();

    // Check if there is a conflicting tx in the blockchain or mempool
    bool CanAddSpendToMempool(const Scalar& coinSerial);

    bool CanAddMintToMempool(const GroupElement& pubCoin);

    // Add spend into the mempool.
    // Check if there is a coin with such serial in either blockchain or mempool
    bool AddSpendToMempool(const std::vector<Scalar>& coinSerials, uint256 txHash);

    void AddMintsToMempool(const std::vector<GroupElement>& pubCoins);
    void RemoveMintFromMempool(const GroupElement& pubCoin);

    // Get conflicting tx hash by coin serial number
    uint256 GetMempoolConflictingTxHash(const Scalar& coinSerial);

    // Remove spend from the mempool (usually as the result of adding tx to the block)
    void RemoveSpendFromMempool(const std::vector<Scalar>& coinSerials);

    static CLelantusState* GetState();

    int GetLatestCoinID() const;

    mint_info_container const & GetMints() const;
    std::unordered_map<Scalar, int> const & GetSpends() const;
    std::unordered_map<int, LelantusCoinGroupInfo> const & GetCoinGroups() const ;
    std::unordered_map<Scalar, uint256, sigma::CScalarHash> const & GetMempoolCoinSerials() const;

    std::size_t GetTotalCoins() const { return GetMints().size(); }

    bool IsSurgeConditionDetected() const;

private:
    size_t CountLastNCoins(int groupId, size_t required, CBlockIndex* &first);

private:
    // Group Limit
    size_t maxCoinInGroup;
    size_t startGroupSize;

    // Collection of coin groups. Map from id to LelantusCoinGroupInfo structure
    std::unordered_map<int, LelantusCoinGroupInfo> coinGroups;

    // Latest anonymity set id;
    int latestCoinId;

    std::atomic<bool> surgeCondition;

    struct Containers {
        Containers(std::atomic<bool> & surgeCondition);

        void AddMint(lelantus::PublicCoin const & pubCoin, CMintedCoinInfo const & coinInfo, const uint256& tag);
        void RemoveMint(lelantus::PublicCoin const & pubCoin);

        void AddSpend(Scalar const & serial, int coinGroupId);
        void RemoveSpend(Scalar const & serial);

        void AddExtendedMints(int group, size_t mints);
        void RemoveExtendedMints(int group);

        void Reset();

        mint_info_container const & GetMints() const;
        std::unordered_map<Scalar, int> const & GetSpends() const;
        std::unordered_map<uint256, lelantus::PublicCoin>& GetTagToPublicCoin();
        bool IsSurgeCondition() const;
    private:
        // Set of all minted pubCoin values, keyed by the public coin.
        // Used for checking if the given coin already exists.
        mint_info_container mintedPubCoins;
        // Set of all used coin serials.
        std::unordered_map<Scalar, int> usedCoinSerials;

        //this map keeps hash(G^s*H0^r|seedId) to G^s*H0^r*H1^v
        std::unordered_map<uint256, lelantus::PublicCoin> tagToPublicCoin;

        std::atomic<bool> & surgeCondition;

        typedef std::map<int, size_t> metainfo_container_t;
        metainfo_container_t extendedMintMetaInfo, mintMetaInfo, spendMetaInfo;

        void CheckSurgeCondition();

        friend class lelantus_mintspend::lelantus_mintspend_test;
    };

    Containers containers;

    friend class lelantus_mintspend::lelantus_mintspend_test;
};

} // end of namespace lelantus

#endif // _MAIN_LELANTUS_H__
