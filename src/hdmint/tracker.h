// Copyright (c) 2019 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_HDMINTTRACKER_H
#define FIRO_HDMINTTRACKER_H

#include "primitives/mint_spend.h"
#include "hdmint/mintpool.h"
#include "wallet/walletdb.h"
#include <list>

class CHDMint;
class CHDMintWallet;

class CHDMintTracker
{
private:
    bool fInitialized;
    std::string strWalletFile;
    std::map<uint256, CMintMeta> mapSerialHashes;
    std::map<uint256, CLelantusMintMeta> mapLelantusSerialHashes;
    std::map<uint256, uint256> mapPendingSpends; //serialhash, txid of spend
    bool IsMempoolSpendOurs(const std::set<uint256>& setMempool, const uint256& hashSerial);
    bool UpdateMetaStatus(const std::set<uint256>& setMempool, CMintMeta& mint, bool fSpend=false);
    bool UpdateLelantusMetaStatus(const std::set<uint256>& setMempool, CLelantusMintMeta& mint, bool fSpend=false);

    std::set<uint256> GetMempoolTxids();
public:
    CHDMintTracker(std::string strWalletFile);
    ~CHDMintTracker();
    void Add(CWalletDB& walletdb, const CHDMint& dMint, bool isNew = false, bool isArchived = false);
    void AddLelantus(CWalletDB& walletdb, const CHDMint& dMint, bool isNew = false, bool isArchived = false);
    void Add(CWalletDB& walletdb, const CSigmaEntry& sigma, bool isNew = false, bool isArchived = false);
    bool Archive(CMintMeta& meta);
    bool Archive(CLelantusMintMeta& meta);
    bool HasSigmaPubcoinHash(const uint256& hashPubcoin, CWalletDB& walletdb) const;
    bool HasLelantusPubcoinHash(const uint256& hashPubcoin, CWalletDB& walletdb) const;
    bool HasSerialHash(const uint256& hashSerial) const;
    bool HasLelantusSerialHash(const uint256& hashSerial) const;
    bool IsEmpty() const { return mapSerialHashes.empty(); }
    void Init();
    bool GetMetaFromSerial(const uint256& hashSerial, CMintMeta& mMeta);
    bool GetMetaFromSerial(const uint256& hashSerial, CLelantusMintMeta& mMeta);
    bool GetMetaFromPubcoin(const uint256& hashPubcoin, CMintMeta& mMeta);
    bool GetLelantusMetaFromPubcoin(const uint256& hashPubcoin, CLelantusMintMeta& mMeta);

    std::vector<uint256> GetSerialHashes();
    void UpdateFromBlock(const std::list<std::pair<uint256, MintPoolEntry>>& mintPoolEntries, const std::vector<CMintMeta>& updatedMeta);
    void UpdateFromBlock(const std::list<std::pair<uint256, MintPoolEntry>>& mintPoolEntries, const std::vector<CLelantusMintMeta>& updatedMeta);
    void UpdateMintStateFromBlock(const std::vector<sigma::PublicCoin>& mints);
    void UpdateMintStateFromBlock(const std::vector<std::pair<lelantus::PublicCoin, std::pair<uint64_t, uint256>>>& mints);
    void UpdateSpendStateFromBlock(const sigma::spend_info_container& spentSerials);
    void UpdateSpendStateFromBlock(const std::unordered_map<Scalar, int>& spentSerials);
    void UpdateMintStateFromMempool(const std::vector<GroupElement>& pubCoins);
    void UpdateLelantusMintStateFromMempool(const std::vector<GroupElement>& pubCoins, const std::vector<uint64_t>& amounts);
    void UpdateSpendStateFromMempool(const std::vector<Scalar>& spentSerials);
    void UpdateJoinSplitStateFromMempool(const std::vector<Scalar>& spentSerials);
    std::list<CSigmaEntry> MintsAsSigmaEntries(bool fUnusedOnly = true, bool fMatureOnly = true);
    std::list<CLelantusEntry> MintsAsLelantusEntries(bool fUnusedOnly = true, bool fMatureOnly = true);
    std::vector<CMintMeta> ListMints(bool fUnusedOnly = true, bool fMatureOnly = true, bool fUpdateStatus = true, bool fLoad = false, bool fWrongSeed = false);
    std::vector<CLelantusMintMeta> ListLelantusMints(bool fUnusedOnly = true, bool fMatureOnly = true, bool fUpdateStatus = true, bool fLoad = false, bool fWrongSeed = false);
    void SetPubcoinUsed(const uint256& hashPubcoin, const uint256& txid);
    void SetPubcoinNotUsed(const uint256& hashPubcoin);
    void SetLelantusPubcoinUsed(const uint256& hashPubcoin, const uint256& txid);
    void SetLelantusPubcoinNotUsed(const uint256& hashPubcoin);
    bool UnArchive(const uint256& hashPubcoin, bool isDeterministic);
    bool UpdateState(const CMintMeta& meta);
    bool UpdateState(const CLelantusMintMeta& meta);
    void Clear();
};

#endif //FIRO_HDMINTTRACKER_H
