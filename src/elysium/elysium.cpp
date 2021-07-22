#include "elysium.h"

#include "activation.h"
#include "consensushash.h"
#include "convert.h"
#include "errors.h"
#include "lelantusdb.h"
#include "log.h"
#include "notifications.h"
#include "packetencoder.h"
#include "pending.h"
#include "persistence.h"
#include "rules.h"
#include "script.h"
#include "sp.h"
#include "tally.h"
#include "tx.h"
#include "txprocessor.h"
#include "utils.h"
#include "utilsbitcoin.h"
#include "version.h"
#ifdef ENABLE_WALLET
#include "wallet.h"
#endif
#include "walletcache.h"
#include "wallettxs.h"

#include "../base58.h"
#include "../chainparams.h"
#include "../wallet/coincontrol.h"
#include "../coins.h"
#include "../core_io.h"
#include "../init.h"
#include "../validation.h"
#include "../net.h"
#include "../lelantus.h"
#include "../primitives/block.h"
#include "../primitives/transaction.h"
#include "../script/script.h"
#include "../script/standard.h"
#include "../sync.h"
#include "../tinyformat.h"
#include "../uint256.h"
#include "../ui_interface.h"
#include "../util.h"
#include "../utilstrencodings.h"
#include "../utiltime.h"
#ifdef ENABLE_WALLET
#include "../script/ismine.h"
#include "../wallet/wallet.h"
#endif

#include <univalue.h>

#include <boost/algorithm/string.hpp>
#include <boost/exception/to_string.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>

#include <openssl/sha.h>

#include "leveldb/db.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include <fstream>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

using boost::algorithm::token_compress_on;
using boost::to_string;

using leveldb::Iterator;
using leveldb::Slice;
using leveldb::Status;

using std::endl;
using std::make_pair;
using std::map;
using std::ofstream;
using std::pair;
using std::string;
using std::vector;

using namespace elysium;

static int nWaterlineBlock = 0;

//! Available balances of wallet properties
std::map<uint32_t, int64_t> global_balance_money;
//! Reserved balances of wallet propertiess
std::map<uint32_t, int64_t> global_balance_reserved;
//! Vector containing a list of properties relative to the wallet
std::set<uint32_t> global_wallet_property_list;

//! Set containing properties that have freezing enabled
std::set<std::pair<uint32_t,int> > setFreezingEnabledProperties;
//! Set containing addresses that have been frozen
std::set<std::pair<std::string,uint32_t> > setFrozenAddresses;

/**
 * Used to indicate, whether to automatically commit created transactions.
 *
 * Can be set with configuration "-autocommit" or RPC "setautocommit_ELYSIUM".
 */
bool autoCommit = true;

//! Number of "Dev ELYSIUM" of the last processed block
static int64_t elysium_prev = 0;

static boost::filesystem::path MPPersistencePath;

static int elysiumInitialized = 0;

static int reorgRecoveryMode = 0;
static int reorgRecoveryMaxHeight = 0;

CMPTxList *elysium::p_txlistdb;
CMPSTOList *elysium::s_stolistdb;
CElysiumTransactionDB *elysium::p_ElysiumTXDB;

// indicate whether persistence is enabled at this point, or not
// used to write/read files, for breakout mode, debugging, etc.
static bool writePersistence(int block_now)
{
  // if too far away from the top -- do not write
  if (GetHeight() > (block_now + MAX_STATE_HISTORY)) return false;

  return true;
}

bool isElysiumEnabled()
{
    return GetBoolArg("-elysium", false);
}

std::string elysium::strMPProperty(uint32_t propertyId)
{
    std::string str = "*unknown*";

    // test user-token
    if (0x80000000 & propertyId) {
        str = strprintf("Test token: %d : 0x%08X", 0x7FFFFFFF & propertyId, propertyId);
    } else {
        switch (propertyId) {
            case ELYSIUM_PROPERTY_FIRO: str = "FIRO";
                break;
            case ELYSIUM_PROPERTY_ELYSIUM: str = "ELYSIUM";
                break;
            case ELYSIUM_PROPERTY_TELYSIUM: str = "TELYSIUM";
                break;
            default:
                str = strprintf("SP token: %d", propertyId);
        }
    }

    return str;
}

std::string FormatDivisibleShortMP(int64_t n)
{
    int64_t n_abs = (n > 0 ? n : -n);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    std::string str = strprintf("%d.%08d", quotient, remainder);
    // clean up trailing zeros - good for RPC not so much for UI
    str.erase(str.find_last_not_of('0') + 1, std::string::npos);
    if (str.length() > 0) {
        std::string::iterator it = str.end() - 1;
        if (*it == '.') {
            str.erase(it);
        }
    } //get rid of trailing dot if non decimal
    return str;
}

std::string FormatDivisibleMP(int64_t n, bool fSign)
{
    // Note: not using straight sprintf here because we do NOT want
    // localized number formatting.
    int64_t n_abs = (n > 0 ? n : -n);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    std::string str = strprintf("%d.%08d", quotient, remainder);

    if (!fSign) return str;

    if (n < 0)
        str.insert((unsigned int) 0, 1, '-');
    else
        str.insert((unsigned int) 0, 1, '+');
    return str;
}

std::string elysium::FormatIndivisibleMP(int64_t n)
{
    return strprintf("%d", n);
}

std::string FormatShortMP(uint32_t property, int64_t n)
{
    if (isPropertyDivisible(property)) {
        return FormatDivisibleShortMP(n);
    } else {
        return FormatIndivisibleMP(n);
    }
}

std::string FormatMP(uint32_t property, int64_t n, bool fSign)
{
    if (isPropertyDivisible(property)) {
        return FormatDivisibleMP(n, fSign);
    } else {
        return FormatIndivisibleMP(n);
    }
}

std::string FormatByType(int64_t amount, uint16_t propertyType)
{
    if (propertyType & ELYSIUM_PROPERTY_TYPE_INDIVISIBLE) {
        return FormatIndivisibleMP(amount);
    } else {
        return FormatDivisibleMP(amount);
    }
}

CMPSPInfo *elysium::_my_sps;

// this is the master list of all amounts for all addresses for all properties, map is unsorted
std::unordered_map<std::string, CMPTally> elysium::mp_tally_map;

CMPTally* elysium::getTally(const std::string& address)
{
    std::unordered_map<std::string, CMPTally>::iterator it = mp_tally_map.find(address);

    if (it != mp_tally_map.end()) return &(it->second);

    return (CMPTally *) NULL;
}

// look at balance for an address
int64_t getMPbalance(const std::string& address, uint32_t propertyId, TallyType ttype)
{
    int64_t balance = 0;
    if (TALLY_TYPE_COUNT <= ttype) {
        return 0;
    }

    LOCK(cs_main);
    const std::unordered_map<std::string, CMPTally>::iterator my_it = mp_tally_map.find(address);
    if (my_it != mp_tally_map.end()) {
        balance = (my_it->second).getMoney(propertyId, ttype);
    }

    return balance;
}

int64_t getUserAvailableMPbalance(const std::string& address, uint32_t propertyId)
{
    int64_t money = getMPbalance(address, propertyId, BALANCE);
    int64_t pending = getMPbalance(address, propertyId, PENDING);

    if (0 > pending) {
        return (money + pending); // show the decrease in available money
    }

    return money;
}

int64_t getUserFrozenMPbalance(const std::string& address, uint32_t propertyId)
{
    int64_t frozen = 0;

    if (isAddressFrozen(address, propertyId)) {
        frozen = getMPbalance(address, propertyId, BALANCE);
    }

    return frozen;
}

bool elysium::isTestEcosystemProperty(uint32_t propertyId)
{
    if ((ELYSIUM_PROPERTY_TELYSIUM == propertyId) || (TEST_ECO_PROPERTY_1 <= propertyId)) return true;

    return false;
}

bool elysium::isMainEcosystemProperty(uint32_t propertyId)
{
    if ((ELYSIUM_PROPERTY_FIRO != propertyId) && !isTestEcosystemProperty(propertyId)) return true;

    return false;
}

void elysium::ClearFreezeState()
{
    // Should only ever be called in the event of a reorg
    setFreezingEnabledProperties.clear();
    setFrozenAddresses.clear();
}

void elysium::PrintFreezeState()
{
    PrintToLog("setFrozenAddresses state:\n");
    for (std::set<std::pair<std::string,uint32_t> >::iterator it = setFrozenAddresses.begin(); it != setFrozenAddresses.end(); it++) {
        PrintToLog("  %s:%d\n", (*it).first, (*it).second);
    }
    PrintToLog("setFreezingEnabledProperties state:\n");
    for (std::set<std::pair<uint32_t,int> >::iterator it = setFreezingEnabledProperties.begin(); it != setFreezingEnabledProperties.end(); it++) {
        PrintToLog("  %d:%d\n", (*it).first, (*it).second);
    }
}

void elysium::enableFreezing(uint32_t propertyId, int liveBlock)
{
    setFreezingEnabledProperties.insert(std::make_pair(propertyId, liveBlock));
    assert(isFreezingEnabled(propertyId, liveBlock));
    PrintToLog("Freezing for property %d will be enabled at block %d.\n", propertyId, liveBlock);
}

void elysium::disableFreezing(uint32_t propertyId)
{
    int liveBlock = 0;
    for (std::set<std::pair<uint32_t,int> >::iterator it = setFreezingEnabledProperties.begin(); it != setFreezingEnabledProperties.end(); it++) {
        if (propertyId == (*it).first) {
            liveBlock = (*it).second;
        }
    }
    assert(liveBlock > 0);

    setFreezingEnabledProperties.erase(std::make_pair(propertyId, liveBlock));
    PrintToLog("Freezing for property %d has been disabled.\n", propertyId);

    // When disabling freezing for a property, all frozen addresses for that property will be unfrozen!
    for (std::set<std::pair<std::string,uint32_t> >::iterator it = setFrozenAddresses.begin(); it != setFrozenAddresses.end(); ) {
        if ((*it).second == propertyId) {
            PrintToLog("Address %s has been unfrozen for property %d.\n", (*it).first, propertyId);
            it = setFrozenAddresses.erase(it);
            assert(!isAddressFrozen((*it).first, (*it).second));
        } else {
            it++;
        }
    }

    assert(!isFreezingEnabled(propertyId, liveBlock));
}

bool elysium::isFreezingEnabled(uint32_t propertyId, int block)
{
    for (std::set<std::pair<uint32_t,int> >::iterator it = setFreezingEnabledProperties.begin(); it != setFreezingEnabledProperties.end(); it++) {
        uint32_t itemPropertyId = (*it).first;
        int itemBlock = (*it).second;
        if (propertyId == itemPropertyId && block >= itemBlock) {
            return true;
        }
    }
    return false;
}

void elysium::freezeAddress(const std::string& address, uint32_t propertyId)
{
    setFrozenAddresses.insert(std::make_pair(address, propertyId));
    assert(isAddressFrozen(address, propertyId));
    PrintToLog("Address %s has been frozen for property %d.\n", address, propertyId);
}

void elysium::unfreezeAddress(const std::string& address, uint32_t propertyId)
{
    setFrozenAddresses.erase(std::make_pair(address, propertyId));
    assert(!isAddressFrozen(address, propertyId));
    PrintToLog("Address %s has been unfrozen for property %d.\n", address, propertyId);
}

bool elysium::isAddressFrozen(const std::string& address, uint32_t propertyId)
{
    if (setFrozenAddresses.find(std::make_pair(address, propertyId)) != setFrozenAddresses.end()) {
        return true;
    }
    return false;
}

std::string elysium::getTokenLabel(uint32_t propertyId)
{
    std::string tokenStr;
    if (propertyId < 3) {
        if (propertyId == 1) {
            tokenStr = " ELYSIUM";
        } else {
            tokenStr = " TELYSIUM";
        }
    } else {
        tokenStr = strprintf(" SPT#%d", propertyId);
    }
    return tokenStr;
}

// get total tokens for a property
// optionally counts the number of addresses who own that property: n_owners_total
int64_t elysium::getTotalTokens(uint32_t propertyId, int64_t* n_owners_total)
{
    int64_t prev = 0;
    int64_t owners = 0;
    int64_t totalTokens = 0;

    LOCK(cs_main);

    CMPSPInfo::Entry property;
    if (false == _my_sps->getSP(propertyId, property)) {
        return 0; // property ID does not exist
    }

    if (!property.fixed || n_owners_total) {
        for (std::unordered_map<std::string, CMPTally>::const_iterator it = mp_tally_map.begin(); it != mp_tally_map.end(); ++it) {
            const CMPTally& tally = it->second;

            totalTokens += tally.getMoney(propertyId, BALANCE);

            if (prev != totalTokens) {
                prev = totalTokens;
                owners++;
            }
        }
        // int64_t cachedFee = p_feecache->GetCachedAmount(propertyId);
        // totalTokens += cachedFee;
    }

    if (property.fixed) {
        totalTokens = property.num_tokens; // only valid for TX50
    }

    if (n_owners_total) *n_owners_total = owners;

    return totalTokens;
}

// return true if everything is ok
bool elysium::update_tally_map(const std::string& who, uint32_t propertyId, int64_t amount, TallyType ttype)
{
    if (0 == amount) {
        PrintToLog("%s(%s, %u=0x%X, %+d, ttype=%d) ERROR: amount to credit or debit is zero\n", __func__, who, propertyId, propertyId, amount, ttype);
        return false;
    }
    if (ttype >= TALLY_TYPE_COUNT) {
        PrintToLog("%s(%s, %u=0x%X, %+d, ttype=%d) ERROR: invalid tally type\n", __func__, who, propertyId, propertyId, amount, ttype);
        return false;
    }

    bool bRet = false;
    int64_t before = 0;
    int64_t after = 0;

    LOCK(cs_main);

    if (ttype == BALANCE && amount < 0) {
        assert(!isAddressFrozen(who, propertyId)); // for safety, this should never fail if everything else is working properly.
    }

    before = getMPbalance(who, propertyId, ttype);

    std::unordered_map<std::string, CMPTally>::iterator my_it = mp_tally_map.find(who);
    if (my_it == mp_tally_map.end()) {
        // insert an empty element
        my_it = (mp_tally_map.insert(std::make_pair(who, CMPTally()))).first;
    }

    CMPTally& tally = my_it->second;
    bRet = tally.updateMoney(propertyId, amount, ttype);

    after = getMPbalance(who, propertyId, ttype);
    if (!bRet) {
        assert(before == after);
        PrintToLog("%s(%s, %u=0x%X, %+d, ttype=%d) ERROR: insufficient balance (=%d)\n", __func__, who, propertyId, propertyId, amount, ttype, before);
    }
    if (elysium_debug_tally && (CBitcoinAddress(who) != GetSystemAddress() || elysium_debug_ely)) {
        PrintToLog("%s(%s, %u=0x%X, %+d, ttype=%d): before=%d, after=%d\n", __func__, who, propertyId, propertyId, amount, ttype, before, after);
    }

    return bRet;
}

uint32_t elysium::GetNextPropertyId(bool maineco)
{
    if (maineco) {
        return _my_sps->peekNextSPID(1);
    } else {
        return _my_sps->peekNextSPID(2);
    }
}

void CheckWalletUpdate(bool forceUpdate)
{
    if (!WalletCacheUpdate()) {
        // no balance changes were detected that affect wallet addresses, signal a generic change to overall Elysium state
        if (!forceUpdate) {
            uiInterface.ElysiumStateChanged();
            return;
        }
    }
#ifdef ENABLE_WALLET
    LOCK(cs_main);

    // balance changes were found in the wallet, update the global totals and signal a Elysium balance change
    global_balance_money.clear();
    global_balance_reserved.clear();

    // populate global balance totals and wallet property list - note global balances do not include additional balances from watch-only addresses
    for (std::unordered_map<std::string, CMPTally>::iterator my_it = mp_tally_map.begin(); my_it != mp_tally_map.end(); ++my_it) {
        // check if the address is a wallet address (including watched addresses)
        std::string address = my_it->first;
        int addressIsMine = IsMyAddress(address);
        if (!addressIsMine) continue;
        // iterate only those properties in the TokenMap for this address
        my_it->second.init();
        uint32_t propertyId;
        while (0 != (propertyId = (my_it->second).next())) {
            // add to the global wallet property list
            global_wallet_property_list.insert(propertyId);
            // check if the address is spendable (only spendable balances are included in totals)
            if (addressIsMine != ISMINE_SPENDABLE) continue;
            // work out the balances and add to globals
            global_balance_money[propertyId] += getUserAvailableMPbalance(address, propertyId);
        }
    }
    // signal an Elysium balance change
    uiInterface.ElysiumBalanceChanged();
#endif
}

// TODO: move
CCoinsView elysium::viewDummy;
CCoinsViewCache elysium::view(&viewDummy);

static unsigned int nCacheHits = 0;
static unsigned int nCacheMiss = 0;

/**
 * Fetches transaction inputs and adds them to the coins view cache.
 *
 * Note: cs_main should be locked, when adding and accessing inputs!
 *
 * @param tx[in]  The transaction to fetch inputs for
 * @return True, if all inputs were successfully added to the cache
 */
static bool FillTxInputCache(const CTransaction& tx)
{
    AssertLockHeld(cs_main);

    static unsigned int nCacheSize = GetArg("-elysiumtxcache", 500000);

    if (view.GetCacheSize() > nCacheSize) {
        PrintToLog("%s(): clearing cache before insertion [size=%d, hit=%d, miss=%d]\n",
                __func__, view.GetCacheSize(), nCacheHits, nCacheMiss);
        view.Flush();
    }

    for (std::vector<CTxIn>::const_iterator it = tx.vin.begin(); it != tx.vin.end(); ++it) {
        const CTxIn& txIn = *it;

        if (it->scriptSig.IsLelantusJoinSplit()) {
            continue;
        }

        unsigned int nOut = txIn.prevout.n;
        Coin coin = view.AccessCoin(txIn.prevout);

        if (!coin.IsSpent()) {
            ++nCacheHits;
            continue;
        } else {
            ++nCacheMiss;
        }

        CTransactionRef txPrev;
        uint256 hashBlock;
        if (!GetTransaction(txIn.prevout.hash, txPrev, Params().GetConsensus(), hashBlock, true)) {
            return false;
        }

        coin.out.scriptPubKey = txPrev->vout[nOut].scriptPubKey;
        coin.out.nValue = txPrev->vout[nOut].nValue;
        view.AddCoin(txIn.prevout, std::move(coin), true);
    }

    return true;
}

// idx is position within the block, 0-based
// int elysium_tx_push(const CTransaction &wtx, int nBlock, unsigned int idx)
// INPUT: bRPConly -- set to true to avoid moving funds; to be called from various RPC calls like this
// RETURNS: 0 if parsed a MP TX
// RETURNS: < 0 if a non-MP-TX or invalid
// RETURNS: >0 if 1 or more payments have been made
static int parseTransaction(bool bRPConly, const CTransaction& wtx, int nBlock, unsigned int idx, CMPTransaction& mp_tx, unsigned int nTime)
{
    InputMode inputMode = InputMode::NORMAL;

	if (wtx.IsLelantusJoinSplit()) {
        inputMode = InputMode::LELANTUS;
    }

    assert(bRPConly == mp_tx.isRpcOnly());
    mp_tx.Set(wtx.GetHash(), nBlock, idx, nTime);

    // ### CLASS IDENTIFICATION AND MARKER CHECK ###
	boost::optional<PacketClass> elysiumClass = DeterminePacketClass(wtx, nBlock);

	if (elysiumClass == PacketClass::C) {
		LogPrintf("Class C\n");
	} 

    if (!elysiumClass) {
        return -1; // No Elysium/Elysium marker, thus not a valid Elysium transaction
    }

    if (!bRPConly || elysium_debug_parser_readonly) {
		LogPrintf("____________________________________________________________________________________________________________________________________\n");
		LogPrintf("%s(block=%d, %s idx= %d); txid: %s\n", __FUNCTION__, nBlock, DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nTime), idx, wtx.GetHash().GetHex());
    }

    // ### SENDER IDENTIFICATION ###
    boost::optional<CBitcoinAddress> sender;
    int64_t inAll = 0;

    { // needed to ensure the cache isn't cleared in the meantime when doing parallel queries
    LOCK(cs_main);

    // Add previous transaction inputs to the cache
    if (!FillTxInputCache(wtx)) {
		LogPrintf("%s() ERROR: failed to get inputs for %s\n", __func__, wtx.GetHash().GetHex());
        return -101;
    }

    assert(view.HaveInputs(wtx));

    if (elysiumClass != PacketClass::C) {
        if (inputMode != InputMode::NORMAL) {
            PrintToLog("%s() ERROR: other input than normal is not allowed when packet class is not C\n", __func__, wtx.GetHash().GetHex());
            return -101;
        }

        // OLD LOGIC - collect input amounts and identify sender via "largest input by sum"
        std::map<CBitcoinAddress, int64_t> inputs_sum_of_values;

        for (unsigned int i = 0; i < wtx.vin.size(); ++i) {
            if (elysium_debug_vin) PrintToLog("vin=%d:%s\n", i, ScriptToAsmStr(wtx.vin[i].scriptSig));

            const CTxIn& txIn = wtx.vin[i];
            const Coin& txOut = view.AccessCoin(txIn.prevout);

            CTxDestination source;
            txnouttype whichType;
            if (!GetOutputType(txOut.out.scriptPubKey, whichType)) {
                return -104;
            }
            if (!IsAllowedInputType(whichType, nBlock)) {
                return -105;
            }
            if (ExtractDestination(txOut.out.scriptPubKey, source)) { // extract the destination of the previous transaction's vout[n] and check it's allowed type
                inputs_sum_of_values[CBitcoinAddress(source)] += txOut.out.nValue;
            }
            else return -106;
        }

        int64_t nMax = 0;
        for (auto it = inputs_sum_of_values.begin(); it != inputs_sum_of_values.end(); ++it) { // find largest by sum
            int64_t nTemp = it->second;
            if (nTemp > nMax) {
                sender = it->first;
                if (elysium_debug_ely) PrintToLog("looking for The Sender: %s , nMax=%lu, nTemp=%d\n", sender->ToString(), nMax, nTemp);
                nMax = nTemp;
            }
        }

        if (!sender) {
            PrintToLog("Failed to determine sender for transaction %s\n", wtx.GetHash().GetHex());
            return -5;
        }
    }
    else if (inputMode != InputMode::LELANTUS)
    {
        // NEW LOGIC - the sender is chosen based on the first vin

        // determine the sender, but invalidate transaction, if the input is not accepted

        // do not need to check sigma.

        unsigned int vin_n = 0; // the first input
        // if (elysium_debug_vin) 
		LogPrintf("vin=%d:%s\n", vin_n, ScriptToAsmStr(wtx.vin[vin_n].scriptSig));

        const CTxIn& txIn = wtx.vin[vin_n];
        const Coin& txOut = view.AccessCoin(txIn.prevout);

        txnouttype whichType;
        if (!GetOutputType(txOut.out.scriptPubKey, whichType)) {
            return -108;
        }
        if (!IsAllowedInputType(whichType, nBlock)) {
            return -109;
        }
        CTxDestination source;
        if (ExtractDestination(txOut.out.scriptPubKey, source)) {
            sender = source;
        }
        else return -110;
    }

	if (inputMode == InputMode::LELANTUS) {
		inAll = lelantus::GetSpendTransparentAmount(wtx);
	}else{
        inAll = view.GetValueIn(wtx);
    }

    } // end of LOCK(cs_main)

    int64_t outAll = wtx.GetValueOut();

    // ### DATA POPULATION ### - save output addresses, values and scripts
    boost::optional<CBitcoinAddress> referenceAddr;
    boost::optional<CAmount> referenceAmount;
    std::vector<unsigned char> payload;
    std::vector<CBitcoinAddress> address_data;
    std::vector<CAmount> value_data;

    for (unsigned int n = 0; n < wtx.vout.size(); ++n) {
        txnouttype whichType;
        if (!GetOutputType(wtx.vout[n].scriptPubKey, whichType)) {
            continue;
        }
        if (!IsAllowedOutputType(whichType, nBlock)) {
            continue;
        }
        CTxDestination dest;
        if (ExtractDestination(wtx.vout[n].scriptPubKey, dest)) {
            CBitcoinAddress address(dest);
            if (address != GetSystemAddress()) {
                // saving for reference
                address_data.push_back(address);
                value_data.push_back(wtx.vout[n].nValue);
                LogPrintf("saving address_data #%d: %s:%s\n", n, address.ToString(), ScriptToAsmStr(wtx.vout[n].scriptPubKey));
            }
        }
    }
    LogPrintf("address_data.size=%lu value_data.size=%lu\n", address_data.size(), value_data.size());

    // ### CLASS C PARSING ###
    LogPrintf("Beginning reference identification\n");

    bool changeRemoved = false; // bool to hold whether we've ignored the first output to sender as change
    unsigned int potentialReferenceOutputs = 0; // int to hold number of potential reference outputs
    for (unsigned k = 0; k < address_data.size(); ++k) { // how many potential reference outputs do we have, if just one select it right here
        auto& addr = address_data[k];
        LogPrintf("ref? data[%d]: %s (%s)\n", k, addr.ToString(), FormatIndivisibleMP(value_data[k]));

        ++potentialReferenceOutputs;
        if (1 == potentialReferenceOutputs) {
            referenceAddr = addr;
            referenceAmount = value_data[k];
			LogPrintf("Single reference potentially id'd as follows: %s \n", referenceAddr->ToString());
        } else { //as soon as potentialReferenceOutputs > 1 we need to go fishing
            referenceAddr = boost::none; // avoid leaving referenceAddr populated for sanity
            referenceAmount = boost::none;
			LogPrintf("More than one potential reference candidate, blanking referenceAddr, need to go fishing\n");
        }
    }
    if (!referenceAddr) { // do we have a reference now? or do we need to dig deeper
		LogPrintf("Reference has not been found yet, going fishing\n");
        for (unsigned k = 0; k < address_data.size(); ++k) {
            auto& addr = address_data[k];

            if (sender && !changeRemoved && addr == *sender) {
                changeRemoved = true; // per spec ignore first output to sender as change if multiple possible ref addresses
				LogPrintf("Removed change\n");
            } else {
                referenceAddr = addr; // this may be set several times, but last time will be highest vout
                referenceAmount = value_data[k];
				LogPrintf("Resetting referenceAddr as follows: %s \n ", referenceAddr->ToString());
            }
        }
    }

    if (elysiumClass == PacketClass::C) {
        // ### CLASS C SPECIFIC PARSING ###
        std::vector<std::vector<unsigned char>> op_return_script_data;

        // ### POPULATE OP RETURN SCRIPT DATA ###
        for (unsigned int n = 0; n < wtx.vout.size(); ++n) {
            txnouttype whichType;
            if (!GetOutputType(wtx.vout[n].scriptPubKey, whichType)) {
                continue;
            }
            if (!IsAllowedOutputType(whichType, nBlock)) {
                continue;
            }
            if (whichType == TX_NULL_DATA) {
                // only consider outputs, which are explicitly tagged
                std::vector<std::vector<unsigned char>> pushes;

                GetPushedValues(wtx.vout[n].scriptPubKey, std::back_inserter(pushes));

                if (pushes.empty() || pushes[0].size() < magic.size() || !std::equal(magic.begin(), magic.end(), pushes[0].begin())) {
                    continue;
                }

                // Strip out the magic at the very beginning
                pushes[0].erase(pushes[0].begin(), pushes[0].begin() + magic.size());

                op_return_script_data.insert(
                    op_return_script_data.end(),
                    std::make_move_iterator(pushes.begin()),
                    std::make_move_iterator(pushes.end())
                );

				LogPrintf("Class C transaction detected: %s parsed to %s at vout %d\n", wtx.GetHash().GetHex(), HexStr(pushes[0]), n);
                
            }
        }
        // ### EXTRACT PAYLOAD FOR CLASS C ###
        for (unsigned int n = 0; n < op_return_script_data.size(); ++n) {
            if (!op_return_script_data[n].empty()) {
                auto& vch = op_return_script_data[n];
                unsigned int payload_size = vch.size();

                if (payload_size > 0) {
                    payload.insert(payload.end(), vch.begin(), vch.begin() + payload_size);
                }
            }
        }
    }

    // ### SET MP TX INFO ###
	LogPrintf("single_pkt: %s\n", HexStr(payload));

    mp_tx.Set(
        sender ? sender->ToString() : "",
        referenceAddr ? referenceAddr->ToString() : "",
        0,
        wtx.GetHash(),
        nBlock,
        idx,
        payload.data(),
        payload.size(),
        elysiumClass,
        inAll - outAll,
        referenceAmount
    );

    return 0;
}

/**
 * Provides access to parseTransaction in read-only mode.
 */
int ParseTransaction(const CTransaction& tx, int nBlock, unsigned int idx, CMPTransaction& mptx, unsigned int nTime)
{
    return parseTransaction(true, tx, nBlock, idx, mptx, nTime);
}

/**
 * Reports the progress of the initial transaction scanning.
 *
 * The progress is printed to the console, written to the debug log file, and
 * the RPC status, as well as the splash screen progress label, are updated.
 *
 * @see elysium_initial_scan()
 */
class ProgressReporter
{
private:
    const CBlockIndex* m_pblockFirst;
    const CBlockIndex* m_pblockLast;
    const int64_t m_timeStart;

    /** Returns the estimated remaining time in milliseconds. */
    int64_t estimateRemainingTime(double progress) const
    {
        int64_t timeSinceStart = GetTimeMillis() - m_timeStart;

        double timeRemaining = 3600000.0; // 1 hour
        if (progress > 0.0 && timeSinceStart > 0) {
            timeRemaining = (100.0 - progress) / progress * timeSinceStart;
        }

        return static_cast<int64_t>(timeRemaining);
    }

    /** Converts a time span to a human readable string. */
    std::string remainingTimeAsString(int64_t remainingTime) const
    {
        int64_t secondsTotal = 0.001 * remainingTime;
        int64_t hours = secondsTotal / 3600;
        int64_t minutes = secondsTotal / 60;
        int64_t seconds = secondsTotal % 60;

        if (hours > 0) {
            return strprintf("%d:%02d:%02d hours", hours, minutes, seconds);
        } else if (minutes > 0) {
            return strprintf("%d:%02d minutes", minutes, seconds);
        } else {
            return strprintf("%d seconds", seconds);
        }
    }

public:
    ProgressReporter(const CBlockIndex* pblockFirst, const CBlockIndex* pblockLast)
    : m_pblockFirst(pblockFirst), m_pblockLast(pblockLast), m_timeStart(GetTimeMillis())
    {
    }

    /** Prints the current progress to the console and notifies the UI. */
    void update(const CBlockIndex* pblockNow) const
    {
        int nLastBlock = m_pblockLast->nHeight;
        int nCurrentBlock = pblockNow->nHeight;
        unsigned int nFirst = m_pblockFirst->nChainTx;
        unsigned int nCurrent = pblockNow->nChainTx;
        unsigned int nLast = m_pblockLast->nChainTx;

        double dProgress = 100.0 * (nCurrent - nFirst) / (nLast - nFirst);
        int64_t nRemainingTime = estimateRemainingTime(dProgress);

        std::string strProgress = strprintf(
                "Still scanning.. at block %d of %d. Progress: %.2f %%, about %s remaining..\n",
                nCurrentBlock, nLastBlock, dProgress, remainingTimeAsString(nRemainingTime));
        std::string strProgressUI = strprintf(
                "Still scanning.. at block %d of %d.\nProgress: %.2f %% (about %s remaining)",
                nCurrentBlock, nLastBlock, dProgress, remainingTimeAsString(nRemainingTime));

        PrintToLog(strProgress);
        uiInterface.InitMessage(strProgressUI);
    }
};

/**
 * Scans the blockchain for meta transactions.
 *
 * It scans the blockchain, starting at the given block index, to the current
 * tip, much like as if new block were arriving and being processed on the fly.
 *
 * Every 30 seconds the progress of the scan is reported.
 *
 * In case the current block being processed is not part of the active chain, or
 * if a block could not be retrieved from the disk, then the scan stops early.
 * Likewise, global shutdown requests are honored, and stop the scan progress.
 *
 * @see elysium_handler_block_begin()
 * @see elysium_handler_tx()
 * @see elysium_handler_block_end()
 *
 * @param nFirstBlock[in]  The index of the first block to scan
 * @return An exit code, indicating success or failure
 */
static int elysium_initial_scan(int nFirstBlock)
{
    int nTimeBetweenProgressReports = GetArg("-elysiumprogressfrequency", 30);  // seconds
    int64_t nNow = GetTime();
    size_t nTxsTotal = 0, nTxsFoundTotal = 0;
    int nBlock = 999999;
    const int nLastBlock = GetHeight();

    // this function is useless if there are not enough blocks in the blockchain yet!
    if (nFirstBlock < 0 || nLastBlock < nFirstBlock) return -1;
    PrintToLog("Scanning for transactions in block %d to block %d..\n", nFirstBlock, nLastBlock);

    // used to print the progress to the console and notifies the UI
    ProgressReporter progressReporter(chainActive[nFirstBlock], chainActive[nLastBlock]);

    for (nBlock = nFirstBlock; nBlock <= nLastBlock; ++nBlock)
    {
        if (ShutdownRequested()) {
            PrintToLog("Shutdown requested, stop scan at block %d of %d\n", nBlock, nLastBlock);
            break;
        }

        CBlockIndex* pblockindex = chainActive[nBlock];
        if (NULL == pblockindex) break;
        std::string strBlockHash = pblockindex->GetBlockHash().GetHex();

        if (elysium_debug_ely) PrintToLog("%s(%d; max=%d):%s, line %d, file: %s\n",
            __FUNCTION__, nBlock, nLastBlock, strBlockHash, __LINE__, __FILE__);

        if (GetTime() >= nNow + nTimeBetweenProgressReports) {
            progressReporter.update(pblockindex);
            nNow = GetTime();
        }

        // Get block to parse.
        CBlock block;

        if (!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus())) {
            break;
        }

        // Parse block.
        unsigned parsed = 0;

        elysium_handler_block_begin(nBlock, pblockindex);

        for (unsigned i = 0; i < block.vtx.size(); i++) {
            if (elysium_handler_tx(*block.vtx[i], nBlock, i, pblockindex)) {
                parsed++;
            }
        }

        elysium_handler_block_end(nBlock, pblockindex, parsed);

        // Sum total parsed.
        nTxsFoundTotal += parsed;
        nTxsTotal += block.vtx.size();

        if (nBlock % 100 == 0) LogPrintf("Finished scanning block %d\n", nBlock);
    }

    if (nBlock < nLastBlock) {
        PrintToLog("Scan stopped early at block %d of block %d\n", nBlock, nLastBlock);
    }

    PrintToLog("%zu transactions processed, %zu meta transactions found\n", nTxsTotal, nTxsFoundTotal);

    return 0;
}

int input_elysium_balances_string(const std::string& s)
{
    // "address=propertybalancedata"
    std::vector<std::string> addrData;
    boost::split(addrData, s, boost::is_any_of("="), boost::token_compress_on);
    if (addrData.size() != 2) return -1;

    std::string strAddress = addrData[0];

    // split the tuples of properties
    std::vector<std::string> vProperties;
    boost::split(vProperties, addrData[1], boost::is_any_of(";"), boost::token_compress_on);

    std::vector<std::string>::const_iterator iter;
    for (iter = vProperties.begin(); iter != vProperties.end(); ++iter) {
        if ((*iter).empty()) {
            continue;
        }

        // "propertyid:balancedata"
        std::vector<std::string> propertyBalance;
        boost::split(propertyBalance, *iter, boost::is_any_of(":"), boost::token_compress_on);
        if (propertyBalance.size() != 2) return -1;

        uint32_t propertyId = boost::lexical_cast<uint32_t>(propertyBalance[0]);
        int64_t balance = boost::lexical_cast<int64_t>(propertyBalance[1]);

        if (balance) update_tally_map(strAddress, propertyId, balance, BALANCE);
    }

    return 0;
}

// elysium_prev
int input_globals_state_string(const string &s)
{
  uint64_t elysiumPrev;
  unsigned int nextSPID, nextTestSPID;
  std::vector<std::string> vstr;
  boost::split(vstr, s, boost::is_any_of(" ,="), token_compress_on);
  if (3 != vstr.size()) return -1;

  int i = 0;
  elysiumPrev = boost::lexical_cast<uint64_t>(vstr[i++]);
  nextSPID = boost::lexical_cast<unsigned int>(vstr[i++]);
  nextTestSPID = boost::lexical_cast<unsigned int>(vstr[i++]);

  elysium_prev = elysiumPrev;
  _my_sps->init(nextSPID, nextTestSPID);
  return 0;
}

static int elysium_file_load(const string &filename, int what, bool verifyHash = false)
{
  int lines = 0;
  int (*inputLineFunc)(const string &) = NULL;

  SHA256_CTX shaCtx;
  SHA256_Init(&shaCtx);

  switch (what)
  {
    case FILETYPE_BALANCES:
      mp_tally_map.clear();
      inputLineFunc = input_elysium_balances_string;
      break;

   case FILETYPE_GLOBALS:
      inputLineFunc = input_globals_state_string;
      break;

    default:
      return -1;
  }

  if (elysium_debug_persistence)
  {
    LogPrintf("Loading %s ... \n", filename);
    PrintToLog("%s(%s), line %d, file: %s\n", __FUNCTION__, filename, __LINE__, __FILE__);
  }

  std::ifstream file;
  file.open(filename.c_str());
  if (!file.is_open())
  {
    if (elysium_debug_persistence) LogPrintf("%s(%s): file not found, line %d, file: %s\n", __FUNCTION__, filename, __LINE__, __FILE__);
    return -1;
  }

  int res = 0;

  std::string fileHash;
  while (file.good())
  {
    std::string line;
    std::getline(file, line);
    if (line.empty() || line[0] == '#') continue;

    // remove \r if the file came from Windows
    line.erase( std::remove( line.begin(), line.end(), '\r' ), line.end() ) ;

    // record and skip hashes in the file
    if (line[0] == '!') {
      fileHash = line.substr(1);
      continue;
    }

    // update hash?
    if (verifyHash) {
      SHA256_Update(&shaCtx, line.c_str(), line.length());
    }

    if (inputLineFunc) {
      if (inputLineFunc(line) < 0) {
        res = -1;
        break;
      }
    }

    ++lines;
  }

  file.close();

  if (verifyHash && res == 0) {
    // generate and wite the double hash of all the contents written
    uint256 hash1;
    SHA256_Final((unsigned char*)&hash1, &shaCtx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);

    if (false == boost::iequals(hash2.ToString(), fileHash)) {
      PrintToLog("File %s loaded, but failed hash validation!\n", filename);
      res = -1;
    }
  }

  PrintToLog("%s(%s), loaded lines= %d, res= %d\n", __FUNCTION__, filename, lines, res);
  LogPrintf("%s(): file: %s , loaded lines= %d, res= %d\n", __FUNCTION__, filename, lines, res);

  return res;
}

static char const * const statePrefix[NUM_FILETYPES] = {
    "balances",
    "globals",
};

// returns the height of the state loaded
static int load_most_relevant_state()
{
  int res = -1;
  // check the SP database and roll it back to its latest valid state
  // according to the active chain
  uint256 spWatermark;
  if (!_my_sps->getWatermark(spWatermark)) {
    //trigger a full reparse, if the SP database has no watermark
    return -1;
  }

  CBlockIndex const *spBlockIndex = GetBlockIndex(spWatermark);
  if (NULL == spBlockIndex) {
    //trigger a full reparse, if the watermark isn't a real block
    return -1;
  }

  while (NULL != spBlockIndex && false == chainActive.Contains(spBlockIndex)) {
    int remainingSPs = _my_sps->popBlock(spBlockIndex->GetBlockHash());
    if (remainingSPs < 0) {
      // trigger a full reparse, if the levelDB cannot roll back
      return -1;
    } /*else if (remainingSPs == 0) {
      // potential optimization here?
    }*/
    spBlockIndex = spBlockIndex->pprev;
    if (spBlockIndex != NULL) {
        _my_sps->setWatermark(spBlockIndex->GetBlockHash());
    }
  }

  // prepare a set of available files by block hash pruning any that are
  // not in the active chain
  std::set<uint256> persistedBlocks;
  boost::filesystem::directory_iterator dIter(MPPersistencePath);
  boost::filesystem::directory_iterator endIter;
  for (; dIter != endIter; ++dIter) {
    if (false == boost::filesystem::is_regular_file(dIter->status()) || dIter->path().empty()) {
      // skip funny business
      continue;
    }

    std::string fName = (*--dIter->path().end()).string();
    std::vector<std::string> vstr;
    boost::split(vstr, fName, boost::is_any_of("-."), token_compress_on);
    if (  vstr.size() == 3 &&
          boost::equals(vstr[2], "dat")) {
      uint256 blockHash;
      blockHash.SetHex(vstr[1]);
      CBlockIndex *pBlockIndex = GetBlockIndex(blockHash);
      if (pBlockIndex == NULL || false == chainActive.Contains(pBlockIndex)) {
        continue;
      }

      // this is a valid block in the active chain, store it
      persistedBlocks.insert(blockHash);
    }
  }

  // using the SP's watermark after its fixed-up as the tip
  // walk backwards until we find a valid and full set of persisted state files
  // for each block we discard, roll back the SP database
  // Note: to avoid rolling back all the way to the genesis block (which appears as if client is hung) abort after MAX_STATE_HISTORY attempts
  CBlockIndex const *curTip = spBlockIndex;
  int abortRollBackBlock;
  if (curTip != NULL) abortRollBackBlock = curTip->nHeight - (MAX_STATE_HISTORY+1);
  while (NULL != curTip && persistedBlocks.size() > 0 && curTip->nHeight > abortRollBackBlock) {
    if (persistedBlocks.find(spBlockIndex->GetBlockHash()) != persistedBlocks.end()) {
      int success = -1;
      for (int i = 0; i < NUM_FILETYPES; ++i) {
        boost::filesystem::path path = MPPersistencePath / strprintf("%s-%s.dat", statePrefix[i], curTip->GetBlockHash().ToString());
        const std::string strFile = path.string();
        success = elysium_file_load(strFile, i, true);
        if (success < 0) {
          break;
        }
      }

      if (success >= 0) {
        res = curTip->nHeight;
        break;
      }

      // remove this from the persistedBlock Set
      persistedBlocks.erase(spBlockIndex->GetBlockHash());
    }

    // go to the previous block
    if (0 > _my_sps->popBlock(curTip->GetBlockHash())) {
      // trigger a full reparse, if the levelDB cannot roll back
      return -1;
    }
    curTip = curTip->pprev;
    if (curTip != NULL) {
        _my_sps->setWatermark(curTip->GetBlockHash());
    }
  }

  if (persistedBlocks.size() == 0) {
    // trigger a reparse if we exhausted the persistence files without success
    return -1;
  }

  // return the height of the block we settled at
  return res;
}

static int write_elysium_balances(std::ofstream& file, SHA256_CTX* shaCtx)
{
    std::unordered_map<std::string, CMPTally>::iterator iter;
    for (iter = mp_tally_map.begin(); iter != mp_tally_map.end(); ++iter) {
        bool emptyWallet = true;

        std::string lineOut = (*iter).first;
        lineOut.append("=");
        CMPTally& curAddr = (*iter).second;
        curAddr.init();
        uint32_t propertyId = 0;
        while (0 != (propertyId = curAddr.next())) {
            int64_t balance = (*iter).second.getMoney(propertyId, BALANCE);

            // we don't allow 0 balances to read in, so if we don't write them
            // it makes things match up better between persisted state and processed state
            if (0 == balance) {
                continue;
            }

            emptyWallet = false;

            lineOut.append(strprintf("%d:%d;",
                    propertyId,
                    balance));
        }

        if (false == emptyWallet) {
            // add the line to the hash
            SHA256_Update(shaCtx, lineOut.c_str(), lineOut.length());

            // write the line
            file << lineOut << endl;
        }
    }

    return 0;
}

static int write_globals_state(ofstream &file, SHA256_CTX *shaCtx)
{
  unsigned int nextSPID = _my_sps->peekNextSPID(ELYSIUM_PROPERTY_ELYSIUM);
  unsigned int nextTestSPID = _my_sps->peekNextSPID(ELYSIUM_PROPERTY_TELYSIUM);
  std::string lineOut = strprintf("%d,%d,%d",
    elysium_prev,
    nextSPID,
    nextTestSPID);

  // add the line to the hash
  SHA256_Update(shaCtx, lineOut.c_str(), lineOut.length());

  // write the line
  file << lineOut << endl;

  return 0;
}

static int write_state_file( CBlockIndex const *pBlockIndex, int what )
{
  boost::filesystem::path path = MPPersistencePath / strprintf("%s-%s.dat", statePrefix[what], pBlockIndex->GetBlockHash().ToString());
  const std::string strFile = path.string();

  std::ofstream file;
  file.open(strFile.c_str());

  SHA256_CTX shaCtx;
  SHA256_Init(&shaCtx);

  int result = 0;

  switch(what) {
  case FILETYPE_BALANCES:
    result = write_elysium_balances(file, &shaCtx);
    break;

  case FILETYPE_GLOBALS:
    result = write_globals_state(file, &shaCtx);
    break;

  }

  // generate and wite the double hash of all the contents written
  uint256 hash1;
  SHA256_Final((unsigned char*)&hash1, &shaCtx);
  uint256 hash2;
  SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
  file << "!" << hash2.ToString() << endl;

  file.flush();
  file.close();
  return result;
}

static bool is_state_prefix( std::string const &str )
{
  for (int i = 0; i < NUM_FILETYPES; ++i) {
    if (boost::equals(str,  statePrefix[i])) {
      return true;
    }
  }

  return false;
}

static void prune_state_files( CBlockIndex const *topIndex )
{
  // build a set of blockHashes for which we have any state files
  std::set<uint256> statefulBlockHashes;

  boost::filesystem::directory_iterator dIter(MPPersistencePath);
  boost::filesystem::directory_iterator endIter;
  for (; dIter != endIter; ++dIter) {
    std::string fName = dIter->path().empty() ? "<invalid>" : (*--dIter->path().end()).string();
    if (false == boost::filesystem::is_regular_file(dIter->status())) {
      // skip funny business
      PrintToLog("Non-regular file found in persistence directory : %s\n", fName);
      continue;
    }

    std::vector<std::string> vstr;
    boost::split(vstr, fName, boost::is_any_of("-."), token_compress_on);
    if (  vstr.size() == 3 &&
          is_state_prefix(vstr[0]) &&
          boost::equals(vstr[2], "dat")) {
      uint256 blockHash;
      blockHash.SetHex(vstr[1]);
      statefulBlockHashes.insert(blockHash);
    } else {
      PrintToLog("None state file found in persistence directory : %s\n", fName);
    }
  }

  // for each blockHash in the set, determine the distance from the given block
  std::set<uint256>::const_iterator iter;
  for (iter = statefulBlockHashes.begin(); iter != statefulBlockHashes.end(); ++iter) {
    // look up the CBlockIndex for height info
    CBlockIndex const *curIndex = GetBlockIndex(*iter);

    // if we have nothing int the index, or this block is too old..
    if (NULL == curIndex || (topIndex->nHeight - curIndex->nHeight) > MAX_STATE_HISTORY ) {
     if (elysium_debug_persistence)
     {
      if (curIndex) {
        PrintToLog("State from Block:%s is no longer need, removing files (age-from-tip: %d)\n", (*iter).ToString(), topIndex->nHeight - curIndex->nHeight);
      } else {
        PrintToLog("State from Block:%s is no longer need, removing files (not in index)\n", (*iter).ToString());
      }
     }

      // destroy the associated files!
      std::string strBlockHash = iter->ToString();
      for (int i = 0; i < NUM_FILETYPES; ++i) {
        boost::filesystem::path path = MPPersistencePath / strprintf("%s-%s.dat", statePrefix[i], strBlockHash);
		LogPrint("handler", "boost::filesystem::remove(%s / %s)\n", statePrefix[i], strBlockHash);
		if(statePrefix[i] != NULL) boost::filesystem::remove(path);
      }
    }
  }
}

int elysium_save_state( CBlockIndex const *pBlockIndex )
{
    // write the new state as of the given block
    write_state_file(pBlockIndex, FILETYPE_BALANCES);
    write_state_file(pBlockIndex, FILETYPE_GLOBALS);

    // clean-up the directory
    prune_state_files(pBlockIndex);	
    _my_sps->setWatermark(pBlockIndex->GetBlockHash());

    return 0;
}

/**
 * Clears the state of the system.
 */
void clear_all_state()
{
    LOCK(cs_main);

    // Memory based storage
    mp_tally_map.clear();
    my_pending.clear();
    ResetConsensusParams();
    ClearActivations();
    ClearAlerts();
    ClearFreezeState();

    // LevelDB based storage
    _my_sps->Clear();
    p_txlistdb->Clear();
	lelantusDb->Clear();
    s_stolistdb->Clear();
    p_ElysiumTXDB->Clear();
    assert(p_txlistdb->setDBVersion() == DB_VERSION); // new set of databases, set DB version
    elysium_prev = 0;

    // Clear wallet state
#ifdef ENABLE_WALLET
    if (wallet) {
        wallet->ClearAllChainState();
    }
#endif
}

/**
 * Global handler to initialize Elysium Core.
 *
 * @return An exit code, indicating success or failure
 */
int elysium_init()
{
    LOCK(cs_main);

    if (elysiumInitialized) {
        // nothing to do
        return 0;
    }

    PrintToLog("\nInitializing Elysium v%s [%s]\n", ElysiumVersion(), Params().NetworkIDString());
    PrintToLog("Startup time: %s\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()));

    InitDebugLogLevels();
    ShrinkDebugLog();

    // check for --autocommit option and set transaction commit flag accordingly
    if (!GetBoolArg("-autocommit", true)) {
        PrintToLog("Process was started with --autocommit set to false. "
                "Created Elysium transactions will not be committed to wallet or broadcast.\n");
        autoCommit = false;
    }

    // check for --startclean option and delete MP_ folders if present
    bool startClean = false;
    if (GetBoolArg("-startclean", false)) {
        PrintToLog("Process was started with --startclean option, attempting to clear persistence files..\n");
        try {
            boost::filesystem::path persistPath = GetDataDir() / "MP_persist";
            boost::filesystem::path txlistPath = GetDataDir() / "MP_txlist";
			boost::filesystem::path lelantusPath = GetDataDir() / "MP_lelantus";
            boost::filesystem::path spPath = GetDataDir() / "MP_spinfo";
            boost::filesystem::path stoPath = GetDataDir() / "MP_stolist";
            boost::filesystem::path elysiumTXDBPath = GetDataDir() / "Elysium_TXDB";
            if (boost::filesystem::exists(persistPath)) boost::filesystem::remove_all(persistPath);
            if (boost::filesystem::exists(txlistPath)) boost::filesystem::remove_all(txlistPath);
			if (boost::filesystem::exists(lelantusPath)) boost::filesystem::remove_all(lelantusPath);
            if (boost::filesystem::exists(spPath)) boost::filesystem::remove_all(spPath);
            if (boost::filesystem::exists(stoPath)) boost::filesystem::remove_all(stoPath);
            if (boost::filesystem::exists(elysiumTXDBPath)) boost::filesystem::remove_all(elysiumTXDBPath);
            PrintToLog("Success clearing persistence files in datadir %s\n", GetDataDir().string());
            startClean = true;
        } catch (const boost::filesystem::filesystem_error& e) {
            PrintToLog("Failed to delete persistence folders: %s\n", e.what());
        }
    }

    s_stolistdb = new CMPSTOList(GetDataDir() / "MP_stolist", fReindex);
    p_txlistdb = new CMPTxList(GetDataDir() / "MP_txlist", fReindex);
    lelantusDb = new LelantusDb(GetDataDir() / "MP_lelantus", fReindex);
    _my_sps = new CMPSPInfo(GetDataDir() / "MP_spinfo", fReindex);
    p_ElysiumTXDB = new CElysiumTransactionDB(GetDataDir() / "Elysium_TXDB", fReindex);

    MPPersistencePath = GetDataDir() / "MP_persist";
    TryCreateDirectory(MPPersistencePath);

    txProcessor = new TxProcessor();

#ifdef ENABLE_WALLET
    if (pwalletMain) {
        wallet = new Wallet(pwalletMain->strWalletFile);

        if (!pwalletMain->IsLocked()) {
            wallet->ReloadMasterKey();
        }
    } else {
        wallet = nullptr;
    }
#endif

    bool wrongDBVersion = (p_txlistdb->getDBVersion() != DB_VERSION);

    ++elysiumInitialized;

    nWaterlineBlock = load_most_relevant_state();
    bool noPreviousState = (nWaterlineBlock <= 0);

    if (startClean) {
        assert(p_txlistdb->setDBVersion() == DB_VERSION); // new set of databases, set DB version
    } else if (wrongDBVersion) {
        nWaterlineBlock = -1; // force a clear_all_state and parse from start
    }

    if (nWaterlineBlock > 0) {
        PrintToLog("Loading persistent state: OK [block %d]\n", nWaterlineBlock);
    } else {
        std::string strReason = "unknown";
        if (wrongDBVersion) strReason = "client version changed";
        if (noPreviousState) strReason = "no usable previous state found";
        if (startClean) strReason = "-startclean parameter used";
        PrintToLog("Loading persistent state: NONE (%s)\n", strReason);
    }

    if (nWaterlineBlock < 0) {
        // persistence says we reparse!, nuke some stuff in case the partial loads left stale bits
        clear_all_state();
    }

    // legacy code, setting to pre-genesis-block
    int snapshotHeight = ConsensusParams().GENESIS_BLOCK - 1;

    if (nWaterlineBlock < snapshotHeight) {
        nWaterlineBlock = snapshotHeight;
        elysium_prev = 0;
    }

    // advance the waterline so that we start on the next unaccounted for block
    nWaterlineBlock += 1;

    // collect the real Elysium balances available at the snapshot time
    // redundant? do we need to show it both pre-parse and post-parse?  if so let's label the printfs accordingly
    if (elysium_debug_ely) {
        int64_t elysium_balance = getMPbalance(GetSystemAddress().ToString(), ELYSIUM_PROPERTY_ELYSIUM, BALANCE);
        PrintToLog("Elysium balance at start: %s\n", FormatDivisibleMP(elysium_balance));
    }

    // load feature activation messages from txlistdb and process them accordingly
    p_txlistdb->LoadActivations(nWaterlineBlock);

    // load all alerts from levelDB (and immediately expire old ones)
    p_txlistdb->LoadAlerts(nWaterlineBlock);

    // load the state of any freeable properties and frozen addresses from levelDB
    if (!p_txlistdb->LoadFreezeState(nWaterlineBlock)) {
        std::string strShutdownReason = "Failed to load freeze state from levelDB.  It is unsafe to continue.\n";
        PrintToLog(strShutdownReason);
        if (!GetBoolArg("-overrideforcedshutdown", false)) {
            AbortNode(strShutdownReason, strShutdownReason);
        }
    }

    // initial scan
    elysium_initial_scan(nWaterlineBlock);

    // display Elysium balance
    int64_t elysium_balance = getMPbalance(GetSystemAddress().ToString(), ELYSIUM_PROPERTY_ELYSIUM, BALANCE);

    PrintToLog("Elysium balance after initialization: %s\n", FormatDivisibleMP(elysium_balance));
    PrintToLog("Elysium initialization completed\n");

    return 0;
}

/**
 * Global handler to shut down Elysium Core.
 *
 * In particular, the LevelDB databases of the global state objects are closed
 * properly.
 *
 * @return An exit code, indicating success or failure
 */
int elysium_shutdown()
{
    LOCK(cs_main);

#ifdef ENABLE_WALLET
    delete wallet; wallet = nullptr;
#endif
    delete txProcessor; txProcessor = nullptr;
	delete lelantusDb; lelantusDb = nullptr;
    delete p_txlistdb; p_txlistdb = nullptr;
    delete s_stolistdb; s_stolistdb = nullptr;
    delete _my_sps; _my_sps = nullptr;
    delete p_ElysiumTXDB; p_ElysiumTXDB = nullptr;

    elysiumInitialized = 0;

    PrintToLog("Elysium Core shutdown completed\n");
    PrintToLog("Shutdown time: %s\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()));

    return 0;
}

/**
 * This handler is called for every new transaction that comes in (actually in block parsing loop).
 *
 * @return True, if the transaction was a valid Elysium transaction
 */
bool elysium_handler_tx(const CTransaction& tx, int nBlock, unsigned int idx, const CBlockIndex* pBlockIndex)
{
    LOCK(cs_main);

    if (!elysiumInitialized) {
        elysium_init();
    }

    // clear pending, if any
    // NOTE1: Every incoming TX is checked, not just MP-ones because:
    // if for some reason the incoming TX doesn't pass our parser validation steps successfuly, I'd still want to clear pending amounts for that TX.
    // NOTE2: Plus I wanna clear the amount before that TX is parsed by our protocol, in case we ever consider pending amounts in internal calculations.
    PendingDelete(tx.GetHash());

    // we do not care about parsing blocks prior to our waterline (empty blockchain defense)
    if (nBlock < nWaterlineBlock) return false;
    int64_t nBlockTime = pBlockIndex->GetBlockTime();

    CMPTransaction mp_obj;
    mp_obj.unlockLogic();

    bool fFoundTx = false;
    int pop_ret = parseTransaction(false, tx, nBlock, idx, mp_obj, nBlockTime);

    if (0 == pop_ret) {
        int interp_ret = txProcessor->ProcessTx(mp_obj);
		LogPrintf("interp_ret = %d \n", interp_ret);
        if (interp_ret) {
            PrintToLog("!!! interpretPacket() returned %d !!!\n", interp_ret);
        }

        // Only structurally valid transactions get recorded in levelDB
        // PKT_ERROR - 2 = interpret_Transaction failed, structurally invalid payload
        if (interp_ret != PKT_ERROR - 2) {
            bool bValid = (0 <= interp_ret);
            p_txlistdb->recordTX(tx.GetHash(), bValid, nBlock, mp_obj.getType(), mp_obj.getNewAmount());
            p_ElysiumTXDB->RecordTransaction(tx.GetHash(), idx, interp_ret);
        }
        fFoundTx |= (interp_ret == 0);
    }

    if (fFoundTx && elysium_debug_consensus_hash_every_transaction) {
        uint256 consensusHash = GetConsensusHash();
        PrintToLog("Consensus hash for transaction %s: %s\n", tx.GetHash().GetHex(), consensusHash.GetHex());
    }

    return fFoundTx;
}

/**
 * Determines, whether it is valid to use a Class C transaction for a given payload size.
 *
 * @param nDataSize The length of the payload
 * @return True, if Class C is enabled and the payload is small enough
 */
bool elysium::UseEncodingClassC(size_t nDataSize)
{
    size_t nTotalSize = nDataSize + magic.size(); // Marker "elysium"
    bool fDataEnabled = GetBoolArg("-datacarrier", true);
    int nBlockNow = GetHeight();
    if (!IsAllowedOutputType(TX_NULL_DATA, nBlockNow)) {
        fDataEnabled = false;
    }
    return nTotalSize <= nMaxDatacarrierBytes && fDataEnabled;
}

// This function requests the wallet create an Elysium transaction using the supplied parameters and payload
int elysium::WalletTxBuilder(
    const std::string& senderAddress,
    const std::string& receiverAddress,
    const std::string& redemptionAddress,
    int64_t referenceAmount,
    const std::vector<unsigned char>& data,
    uint256& txid,
    std::string& rawHex,
    bool commit,
    InputMode inputMode)
{
	if (inputMode == InputMode::NORMAL) LogPrintf("inputMode Normal \n");
	else if (inputMode == InputMode::LELANTUS) LogPrintf("inputMode Lelantus \n");
#ifdef ENABLE_WALLET
    if (pwalletMain == NULL) return MP_ERR_WALLET_ACCESS;

    // Determine the class to send the transaction via - default is Class C
    bool useClassC = (inputMode == InputMode::NORMAL && !UseEncodingClassC(data.size())) ? false : true;

    // Prepare the transaction - first setup some vars
    CCoinControl coinControl;
    CWalletTx wtxNew;
    int64_t nFeeRet = 0;
    int nChangePosInOut = -1;
    std::string strFailReason;
    std::vector<CTxOut> vecSend;
    CReserveKey reserveKey(pwalletMain);

    // Next, we set the change address to the sender
    CBitcoinAddress addr = CBitcoinAddress(senderAddress);
    coinControl.destChange = addr.Get();

    // Select the inputs
    if (0 >= SelectCoins(senderAddress, coinControl, referenceAmount, inputMode)) {
        switch (inputMode) {
        case InputMode::NORMAL:
            return MP_INPUTS_INVALID;
        case InputMode::LELANTUS:
            return MP_LELANTUS_INPUTS_INVALID;
        }
    }

    // Encode the data outputs
    if (useClassC) {
        try {
            vecSend.push_back(EncodeClassC(data.begin(), data.end()));
        } catch (std::exception& e) {
            PrintToLog("Fail to encode packet with class C: %s\n", e.what());
            return MP_ENCODING_ERROR;
        }
    } else {
        CPubKey redeemingPubKey;

        if (inputMode != InputMode::NORMAL) {
            return MP_INPUTS_INVALID;
        }

        if (!AddressToPubKey(redemptionAddress.empty() ? senderAddress : redemptionAddress, redeemingPubKey)) {
            return MP_REDEMP_BAD_VALIDATION;
        }

        return MP_ENCODING_ERROR;
        
    }

    // Then add a paytopubkeyhash output for the recipient (if needed) - note we do this last as we want this to be the highest vout
    if (!receiverAddress.empty()) {
        CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(receiverAddress).Get());
        vecSend.push_back(CTxOut(referenceAmount > 0 ? referenceAmount : GetDustThreshold(scriptPubKey), scriptPubKey));
    }

    // Now we have what we need to pass to the wallet to create the transaction, perform some checks first

    if (!coinControl.HasSelected()) return MP_ERR_INPUTSELECT_FAIL;

    std::vector<CRecipient> vecRecipients;
    for (size_t i = 0; i < vecSend.size(); ++i) {
        auto& output = vecSend[i];
        CRecipient recipient = {output.scriptPubKey, output.nValue, false};
        vecRecipients.push_back(recipient);
    }

    std::vector<CSigmaEntry> sigmaSpendCoins;
    std::vector<CLelantusEntry> lelantusSpendCoins;
    std::vector<CHDMint> lelantusMintCoins;

    CAmount fee;

	

	if(inputMode == InputMode::NORMAL) {
		LogPrintf("inputMode Normal \n");
		// Ask the wallet to create the transaction (note mining fee determined by Bitcoin Core params)
		if (!pwalletMain->CreateTransaction(vecRecipients, wtxNew, reserveKey, nFeeRet, nChangePosInOut, strFailReason, &coinControl)) {
			PrintToLog("%s: ERROR: wallet transaction creation failed: %s\n", __func__, strFailReason);
			return MP_ERR_CREATE_TX;
		}
	}else if (inputMode == InputMode::LELANTUS) {
		LogPrintf("inputMode Lelantus \n");
		try {
			wtxNew = pwalletMain->CreateLelantusJoinSplitTransaction(
				vecRecipients, fee, {}, lelantusSpendCoins, sigmaSpendCoins, lelantusMintCoins, &coinControl);
		}
		catch (std::exception const &err) {
			PrintToLog("%s: ERROR: wallet transaction creation failed: %s\n", __func__, err.what());
			return MP_ERR_CREATE_LELANTUS_TX;
		}
	}else{
        PrintToLog("%s: ERROR: wallet transaction creation failed: input mode is invalid\n", __func__);
        return MP_ERR_CREATE_TX;
    }

    // If this request is only to create, but not commit the transaction then display it and exit
    if (!commit) {
        rawHex = EncodeHexTx(wtxNew);
        return 0;
    } else {
        // Commit the transaction to the wallet and broadcast)
        PrintToLog("%s: %s; nFeeRet = %d\n", __func__, wtxNew.tx->ToString(), nFeeRet);
        switch (inputMode) {
        case InputMode::NORMAL:
            {
                CValidationState state;
                if (!pwalletMain->CommitTransaction(wtxNew, reserveKey, g_connman.get(), state)) return MP_ERR_COMMIT_TX;
            }
            break;
        case InputMode::LELANTUS:
            try {
                if (!pwalletMain->CommitLelantusTransaction(wtxNew, lelantusSpendCoins, sigmaSpendCoins, lelantusMintCoins)) return MP_ERR_COMMIT_TX;
            } catch (...) {
                return MP_ERR_COMMIT_TX;
            }
            break;
        default:
            return MP_ERR_COMMIT_TX;
        }
        txid = wtxNew.GetHash();
        return 0;
    }
#else
    return MP_ERR_WALLET_ACCESS;
#endif

}

void CElysiumTransactionDB::RecordTransaction(const uint256& txid, uint32_t posInBlock, int processingResult)
{
    assert(pdb);

    const std::string key = txid.ToString();
    const std::string value = strprintf("%d:%d", posInBlock, processingResult);

    Status status = pdb->Put(writeoptions, key, value);
    ++nWritten;
}

std::vector<std::string> CElysiumTransactionDB::FetchTransactionDetails(const uint256& txid)
{
    assert(pdb);
    std::string strValue;
    std::vector<std::string> vTransactionDetails;

    Status status = pdb->Get(readoptions, txid.ToString(), &strValue);
    if (status.ok()) {
        std::vector<std::string> vStr;
        boost::split(vStr, strValue, boost::is_any_of(":"), boost::token_compress_on);
        if (vStr.size() == 2) {
            vTransactionDetails.push_back(vStr[0]);
            vTransactionDetails.push_back(vStr[1]);
        } else {
            PrintToLog("ERROR: Entry (%s) found in ElysiumTXDB with unexpected number of attributes!\n", txid.GetHex());
        }
    } else {
        PrintToLog("ERROR: Entry (%s) could not be loaded from ElysiumTXDB!\n", txid.GetHex());
    }

    return vTransactionDetails;
}

uint32_t CElysiumTransactionDB::FetchTransactionPosition(const uint256& txid)
{
    uint32_t posInBlock = 999999; // setting an initial arbitrarily high value will ensure transaction is always "last" in event of bug/exploit

    std::vector<std::string> vTransactionDetails = FetchTransactionDetails(txid);
    if (vTransactionDetails.size() == 2) {
        posInBlock = boost::lexical_cast<uint32_t>(vTransactionDetails[0]);
    }

    return posInBlock;
}

std::string CElysiumTransactionDB::FetchInvalidReason(const uint256& txid)
{
    int processingResult = -999999;

    std::vector<std::string> vTransactionDetails = FetchTransactionDetails(txid);
    if (vTransactionDetails.size() == 2) {
        processingResult = boost::lexical_cast<int>(vTransactionDetails[1]);
    }

    return error_str(processingResult);
}

std::set<int> CMPTxList::GetSeedBlocks(int startHeight, int endHeight)
{
    std::set<int> setSeedBlocks;

    if (!pdb) return setSeedBlocks;

    Iterator* it = NewIterator();

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string itData = it->value().ToString();
        std::vector<std::string> vstr;
        boost::split(vstr, itData, boost::is_any_of(":"), boost::token_compress_on);
        if (4 != vstr.size()) continue; // unexpected number of tokens
        int block = atoi(vstr[1]);
        if (block >= startHeight && block <= endHeight) {
            setSeedBlocks.insert(block);
        }
    }

    delete it;

    return setSeedBlocks;
}

bool CMPTxList::CheckForFreezeTxs(int blockHeight)
{
    assert(pdb);
    Iterator* it = NewIterator();

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string itData = it->value().ToString();
        std::vector<std::string> vstr;
        boost::split(vstr, itData, boost::is_any_of(":"), token_compress_on);
        if (4 != vstr.size()) continue;
        int block = atoi(vstr[1]);
        if (block < blockHeight) continue;
        uint16_t txtype = atoi(vstr[2]);
        if (txtype == ELYSIUM_TYPE_FREEZE_PROPERTY_TOKENS || txtype == ELYSIUM_TYPE_UNFREEZE_PROPERTY_TOKENS ||
            txtype == ELYSIUM_TYPE_ENABLE_FREEZING || txtype == ELYSIUM_TYPE_DISABLE_FREEZING) {
            delete it;
            return true;
        }
    }

    delete it;
    return false;
}

bool CMPTxList::LoadFreezeState(int blockHeight)
{
    assert(pdb);
    std::vector<std::pair<std::string, uint256> > loadOrder;
    Iterator* it = NewIterator();
    PrintToLog("Loading freeze state from levelDB\n");

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string itData = it->value().ToString();
        std::vector<std::string> vstr;
        boost::split(vstr, itData, boost::is_any_of(":"), token_compress_on);
        if (4 != vstr.size()) continue;
        uint16_t txtype = atoi(vstr[2]);
        if (txtype != ELYSIUM_TYPE_FREEZE_PROPERTY_TOKENS && txtype != ELYSIUM_TYPE_UNFREEZE_PROPERTY_TOKENS &&
            txtype != ELYSIUM_TYPE_ENABLE_FREEZING && txtype != ELYSIUM_TYPE_DISABLE_FREEZING) continue;
        if (atoi(vstr[0]) != 1) continue; // invalid, ignore
        uint256 txid = uint256S(it->key().ToString());
        int txPosition = p_ElysiumTXDB->FetchTransactionPosition(txid);
        std::string sortKey = strprintf("%06d%010d", atoi(vstr[1]), txPosition);
        loadOrder.push_back(std::make_pair(sortKey, txid));
    }

    delete it;

    std::sort (loadOrder.begin(), loadOrder.end());

    for (std::vector<std::pair<std::string, uint256> >::iterator it = loadOrder.begin(); it != loadOrder.end(); ++it) {
        uint256 hash = (*it).second;
        uint256 blockHash;
        CTransactionRef wtx;
        CMPTransaction mp_obj;
        if (!GetTransaction(hash, wtx, Params().GetConsensus(), blockHash, true)) {
            PrintToLog("ERROR: While loading freeze transaction %s: tx in levelDB but does not exist.\n", hash.GetHex());
            return false;
        }
        if (blockHash.IsNull() || (NULL == GetBlockIndex(blockHash))) {
            PrintToLog("ERROR: While loading freeze transaction %s: failed to retrieve block hash.\n", hash.GetHex());
            return false;
        }
        CBlockIndex* pBlockIndex = GetBlockIndex(blockHash);
        if (NULL == pBlockIndex) {
            PrintToLog("ERROR: While loading freeze transaction %s: failed to retrieve block index.\n", hash.GetHex());
            return false;
        }
        int txBlockHeight = pBlockIndex->nHeight;
        if (txBlockHeight > blockHeight) {
            PrintToLog("ERROR: While loading freeze transaction %s: transaction is in the future.\n", hash.GetHex());
            return false;
        }
        if (0 != ParseTransaction(*wtx, txBlockHeight, 0, mp_obj)) {
            PrintToLog("ERROR: While loading freeze transaction %s: failed ParseTransaction.\n", hash.GetHex());
            return false;
        }
        if (!mp_obj.interpret_Transaction()) {
            PrintToLog("ERROR: While loading freeze transaction %s: failed interpret_Transaction.\n", hash.GetHex());
            return false;
        }
        if (ELYSIUM_TYPE_FREEZE_PROPERTY_TOKENS != mp_obj.getType() && ELYSIUM_TYPE_UNFREEZE_PROPERTY_TOKENS != mp_obj.getType() &&
            ELYSIUM_TYPE_ENABLE_FREEZING != mp_obj.getType() && ELYSIUM_TYPE_DISABLE_FREEZING != mp_obj.getType()) {
            PrintToLog("ERROR: While loading freeze transaction %s: levelDB type mismatch, not a freeze transaction.\n", hash.GetHex());
            return false;
        }

        if (0 != txProcessor->ProcessTx(mp_obj)) {
            PrintToLog("ERROR: While loading freeze transaction %s: non-zero return from interpretPacket\n", hash.GetHex());
            return false;
        }

    }

    return true;
}

void CMPTxList::LoadActivations(int blockHeight)
{
    if (!pdb) return;

    Slice skey, svalue;
    Iterator* it = NewIterator();

    PrintToLog("Loading feature activations from levelDB\n");

    std::vector<std::pair<int64_t, uint256> > loadOrder;

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string itData = it->value().ToString();
        std::vector<std::string> vstr;
        boost::split(vstr, itData, boost::is_any_of(":"), token_compress_on);
        if (4 != vstr.size()) continue; // unexpected number of tokens
        if (atoi(vstr[2]) != ELYSIUM_MESSAGE_TYPE_ACTIVATION || atoi(vstr[0]) != 1) continue; // we only care about valid activations
        uint256 txid = uint256S(it->key().ToString());;
        loadOrder.push_back(std::make_pair(atoi(vstr[1]), txid));
    }

    std::sort (loadOrder.begin(), loadOrder.end());

    for (std::vector<std::pair<int64_t, uint256> >::iterator it = loadOrder.begin(); it != loadOrder.end(); ++it) {
        uint256 hash = (*it).second;
        uint256 blockHash;
        CTransactionRef wtx;
        CMPTransaction mp_obj;

        if (!GetTransaction(hash, wtx, Params().GetConsensus(), blockHash, true)) {
            PrintToLog("ERROR: While loading activation transaction %s: tx in levelDB but does not exist.\n", hash.GetHex());
            continue;
        }
        if (blockHash.IsNull() || (NULL == GetBlockIndex(blockHash))) {
            PrintToLog("ERROR: While loading activation transaction %s: failed to retrieve block hash.\n", hash.GetHex());
            continue;
        }
        CBlockIndex* pBlockIndex = GetBlockIndex(blockHash);
        if (NULL == pBlockIndex) {
            PrintToLog("ERROR: While loading activation transaction %s: failed to retrieve block index.\n", hash.GetHex());
            continue;
        }
        int blockHeight = pBlockIndex->nHeight;
        if (0 != ParseTransaction(*wtx, blockHeight, 0, mp_obj)) {
            PrintToLog("ERROR: While loading activation transaction %s: failed ParseTransaction.\n", hash.GetHex());
            continue;
        }
        if (!mp_obj.interpret_Transaction()) {
            PrintToLog("ERROR: While loading activation transaction %s: failed interpret_Transaction.\n", hash.GetHex());
            continue;
        }
        if (ELYSIUM_MESSAGE_TYPE_ACTIVATION != mp_obj.getType()) {
            PrintToLog("ERROR: While loading activation transaction %s: levelDB type mismatch, not an activation.\n", hash.GetHex());
            continue;
        }

        if (0 != txProcessor->ProcessTx(mp_obj)) {
            PrintToLog("ERROR: While loading activation transaction %s: non-zero return from interpretPacket\n", hash.GetHex());
            continue;
        }
    }
    delete it;
    CheckLiveActivations(blockHeight);

    // This alert never expires as long as custom activations are used
    if (IsArgSet("-elysiumactivationallowsender") || IsArgSet("-elysiumactivationignoresender")) {
        AddAlert("elysium", ALERT_CLIENT_VERSION_EXPIRY, std::numeric_limits<uint32_t>::max(),
                 "Authorization for feature activation has been modified.  Data provided by this client should not be trusted.");
    }
}

void CMPTxList::LoadAlerts(int blockHeight)
{
    if (!pdb) return;
    Slice skey, svalue;
    Iterator* it = NewIterator();

    std::vector<std::pair<int64_t, uint256> > loadOrder;

    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string itData = it->value().ToString();
        std::vector<std::string> vstr;
        boost::split(vstr, itData, boost::is_any_of(":"), token_compress_on);
        if (4 != vstr.size()) continue; // unexpected number of tokens
        if (atoi(vstr[2]) != ELYSIUM_MESSAGE_TYPE_ALERT || atoi(vstr[0]) != 1) continue; // not a valid alert
        uint256 txid = uint256S(it->key().ToString());;
        loadOrder.push_back(std::make_pair(atoi(vstr[1]), txid));
    }

    std::sort (loadOrder.begin(), loadOrder.end());

    for (std::vector<std::pair<int64_t, uint256> >::iterator it = loadOrder.begin(); it != loadOrder.end(); ++it) {
        uint256 txid = (*it).second;
        uint256 blockHash;
        CTransactionRef wtx;
        CMPTransaction mp_obj;
        if (!GetTransaction(txid, wtx, Params().GetConsensus(), blockHash, true)) {
            PrintToLog("ERROR: While loading alert %s: tx in levelDB but does not exist.\n", txid.GetHex());
            continue;
        }
        if (0 != ParseTransaction(*wtx, blockHeight, 0, mp_obj)) {
            PrintToLog("ERROR: While loading alert %s: failed ParseTransaction.\n", txid.GetHex());
            continue;
        }
        if (!mp_obj.interpret_Transaction()) {
            PrintToLog("ERROR: While loading alert %s: failed interpret_Transaction.\n", txid.GetHex());
            continue;
        }
        if (ELYSIUM_MESSAGE_TYPE_ALERT != mp_obj.getType()) {
            PrintToLog("ERROR: While loading alert %s: levelDB type mismatch, not an alert.\n", txid.GetHex());
            continue;
        }
        if (!CheckAlertAuthorization(mp_obj.getSender())) {
            PrintToLog("ERROR: While loading alert %s: sender is not authorized to send alerts.\n", txid.GetHex());
            continue;
        }

        if (mp_obj.getAlertType() == 65535) { // set alert type to FFFF to clear previously sent alerts
            DeleteAlerts(mp_obj.getSender());
        } else {
            AddAlert(mp_obj.getSender(), mp_obj.getAlertType(), mp_obj.getAlertExpiry(), mp_obj.getAlertMessage());
        }
    }

    delete it;
    int64_t blockTime = 0;
    CBlockIndex* pBlockIndex = chainActive[blockHeight-1];
    if (pBlockIndex != NULL) {
        blockTime = pBlockIndex->GetBlockTime();
    }
    if (blockTime > 0) {
        CheckExpiredAlerts(blockHeight, blockTime);
    }
}

/*
 * Gets the DB version from txlistdb
 *
 * Returns the current version
 */
int CMPTxList::getDBVersion()
{
    std::string strValue;
    int verDB = 0;

    Status status = pdb->Get(readoptions, "dbversion", &strValue);
    if (status.ok()) {
        verDB = boost::lexical_cast<uint64_t>(strValue);
    }

    if (elysium_debug_txdb) PrintToLog("%s(): dbversion %s status %s, line %d, file: %s\n", __FUNCTION__, strValue, status.ToString(), __LINE__, __FILE__);

    return verDB;
}

/*
 * Sets the DB version for txlistdb
 *
 * Returns the current version after update
 */
int CMPTxList::setDBVersion()
{
    std::string verStr = boost::lexical_cast<std::string>(DB_VERSION);
    Status status = pdb->Put(writeoptions, "dbversion", verStr);

    if (elysium_debug_txdb) PrintToLog("%s(): dbversion %s status %s, line %d, file: %s\n", __FUNCTION__, verStr, status.ToString(), __LINE__, __FILE__);

    return getDBVersion();
}

/**
 * Returns the number of sub records.
 */
int CMPTxList::getNumberOfSubRecords(const uint256& txid)
{
    int numberOfSubRecords = 0;

    std::string strValue;
    Status status = pdb->Get(readoptions, txid.ToString(), &strValue);
    if (status.ok()) {
        std::vector<std::string> vstr;
        boost::split(vstr, strValue, boost::is_any_of(":"), boost::token_compress_on);
        if (4 <= vstr.size()) {
            numberOfSubRecords = boost::lexical_cast<int>(vstr[3]);
        }
    }

    return numberOfSubRecords;
}

int CMPTxList::getMPTransactionCountTotal()
{
    int count = 0;
    Slice skey, svalue;
    Iterator* it = NewIterator();
    for(it->SeekToFirst(); it->Valid(); it->Next())
    {
        skey = it->key();
        if (skey.ToString().length() == 64) { ++count; } //extra entries for cancels and purchases are more than 64 chars long
    }
    delete it;
    return count;
}

int CMPTxList::getMPTransactionCountBlock(int block)
{
    int count = 0;
    Slice skey, svalue;
    Iterator* it = NewIterator();
    for(it->SeekToFirst(); it->Valid(); it->Next())
    {
        skey = it->key();
        svalue = it->value();
        if (skey.ToString().length() == 64)
        {
            string strValue = svalue.ToString();
            std::vector<std::string> vstr;
            boost::split(vstr, strValue, boost::is_any_of(":"), token_compress_on);
            if (4 == vstr.size())
            {
                if (atoi(vstr[1]) == block) { ++count; }
            }
        }
    }
    delete it;
    return count;
}

string CMPTxList::getKeyValue(string key)
{
    if (!pdb) return "";
    string strValue;
    Status status = pdb->Get(readoptions, key, &strValue);
    if (status.ok()) { return strValue; } else { return ""; }
}

/**
 * Retrieves details about a "send all" record.
 */
bool CMPTxList::getSendAllDetails(const uint256& txid, int subSend, uint32_t& propertyId, int64_t& amount)
{
    std::string strKey = strprintf("%s-%d", txid.ToString(), subSend);
    std::string strValue;
    leveldb::Status status = pdb->Get(readoptions, strKey, &strValue);
    if (status.ok()) {
        std::vector<std::string> vstr;
        boost::split(vstr, strValue, boost::is_any_of(":"), boost::token_compress_on);
        if (2 == vstr.size()) {
            propertyId = boost::lexical_cast<uint32_t>(vstr[0]);
            amount = boost::lexical_cast<int64_t>(vstr[1]);
            return true;
        }
    }
    return false;
}

bool CMPTxList::getPurchaseDetails(const uint256 txid, int purchaseNumber, string *buyer, string *seller, uint64_t *vout, uint64_t *propertyId, uint64_t *nValue)
{
    if (!pdb) return 0;
    std::vector<std::string> vstr;
    string strValue;
    Status status = pdb->Get(readoptions, txid.ToString()+"-"+to_string(purchaseNumber), &strValue);
    if (status.ok())
    {
        // parse the string returned
        boost::split(vstr, strValue, boost::is_any_of(":"), token_compress_on);
        // obtain the requisite details
        if (5 == vstr.size())
        {
            *vout = atoi(vstr[0]);
            *buyer = vstr[1];
            *seller = vstr[2];
            *propertyId = atoi(vstr[3]);
            *nValue = boost::lexical_cast<boost::uint64_t>(vstr[4]);;
            return true;
        }
    }
    return false;
}

/**
 * Records a "send all" sub record.
 */
void CMPTxList::recordSendAllSubRecord(const uint256& txid, int subRecordNumber, uint32_t propertyId, int64_t nValue)
{
    std::string strKey = strprintf("%s-%d", txid.ToString(), subRecordNumber);
    std::string strValue = strprintf("%d:%d", propertyId, nValue);

    leveldb::Status status = pdb->Put(writeoptions, strKey, strValue);
    ++nWritten;
    if (elysium_debug_txdb) PrintToLog("%s(): store: %s=%s, status: %s\n", __func__, strKey, strValue, status.ToString());
}

void CMPTxList::recordTX(const uint256 &txid, bool fValid, int nBlock, unsigned int type, uint64_t nValue)
{
  if (!pdb) return;

  // overwrite detection, we should never be overwriting a tx, as that means we have redone something a second time
  // reorgs delete all txs from levelDB above reorg_chain_height
  if (p_txlistdb->exists(txid)) PrintToLog("LEVELDB TX OVERWRITE DETECTION - %s\n", txid.ToString());

const string key = txid.ToString();
const string value = strprintf("%u:%d:%u:%lu", fValid ? 1:0, nBlock, type, nValue);
Status status;

  PrintToLog("%s(%s, valid=%s, block= %d, type= %d, value= %lu)\n",
   __FUNCTION__, txid.ToString(), fValid ? "YES":"NO", nBlock, type, nValue);

  if (pdb)
  {
    status = pdb->Put(writeoptions, key, value);
    ++nWritten;
    if (elysium_debug_txdb) PrintToLog("%s(): %s, line %d, file: %s\n", __FUNCTION__, status.ToString(), __LINE__, __FILE__);
  }
}

bool CMPTxList::exists(const uint256 &txid)
{
  if (!pdb) return false;

string strValue;
Status status = pdb->Get(readoptions, txid.ToString(), &strValue);

  if (!status.ok())
  {
    if (status.IsNotFound()) return false;
  }

  return true;
}

bool CMPTxList::getTX(const uint256 &txid, string &value)
{
Status status = pdb->Get(readoptions, txid.ToString(), &value);

  ++nRead;

  if (status.ok())
  {
    return true;
  }

  return false;
}

void CMPTxList::printStats()
{
  PrintToLog("CMPTxList stats: nWritten= %d , nRead= %d\n", nWritten, nRead);
}

void CMPTxList::printAll()
{
int count = 0;
Slice skey, svalue;
  Iterator* it = NewIterator();

  for(it->SeekToFirst(); it->Valid(); it->Next())
  {
    skey = it->key();
    svalue = it->value();
    ++count;
    PrintToLog("entry #%8d= %s:%s\n", count, skey.ToString(), svalue.ToString());
  }

  delete it;
}

// figure out if there was at least 1 Master Protocol transaction within the block range, or a block if starting equals ending
// block numbers are inclusive
// pass in bDeleteFound = true to erase each entry found within the block range
bool CMPTxList::isMPinBlockRange(int starting_block, int ending_block, bool bDeleteFound)
{
leveldb::Slice skey, svalue;
unsigned int count = 0;
std::vector<std::string> vstr;
int block;
unsigned int n_found = 0;

  leveldb::Iterator* it = NewIterator();

  for(it->SeekToFirst(); it->Valid(); it->Next())
  {
    skey = it->key();
    svalue = it->value();

    ++count;

    string strvalue = it->value().ToString();

    // parse the string returned, find the validity flag/bit & other parameters
    boost::split(vstr, strvalue, boost::is_any_of(":"), token_compress_on);

    // only care about the block number/height here
    if (2 <= vstr.size())
    {
      block = atoi(vstr[1]);

      if ((starting_block <= block) && (block <= ending_block))
      {
        ++n_found;
        PrintToLog("%s() DELETING: %s=%s\n", __FUNCTION__, skey.ToString(), svalue.ToString());
        if (bDeleteFound) pdb->Delete(writeoptions, skey);
      }
    }
  }

  PrintToLog("%s(%d, %d); n_found= %d\n", __FUNCTION__, starting_block, ending_block, n_found);

  delete it;

  return (n_found);
}

// MPSTOList here
std::string CMPSTOList::getMySTOReceipts(string filterAddress)
{
  if (!pdb) return "";
  string mySTOReceipts = "";
  Slice skey, svalue;
  Iterator* it = NewIterator();
  for(it->SeekToFirst(); it->Valid(); it->Next()) {
      skey = it->key();
      string recipientAddress = skey.ToString();
      if(!IsMyAddress(recipientAddress)) continue; // not ours, not interested
      if((!filterAddress.empty()) && (filterAddress != recipientAddress)) continue; // not the filtered address
      // ours, get info
      svalue = it->value();
      string strValue = svalue.ToString();
      // break into individual receipts
      std::vector<std::string> vstr;
      boost::split(vstr, strValue, boost::is_any_of(","), token_compress_on);
      for(uint32_t i = 0; i<vstr.size(); i++) {
          // add to array
          std::vector<std::string> svstr;
          boost::split(svstr, vstr[i], boost::is_any_of(":"), token_compress_on);
          if(4 == svstr.size()) {
              size_t txidMatch = mySTOReceipts.find(svstr[0]);
              if(txidMatch==std::string::npos) mySTOReceipts += svstr[0]+":"+svstr[1]+":"+recipientAddress+":"+svstr[2]+",";
          }
      }
  }
  delete it;
  // above code will leave a trailing comma - strip it
  if (mySTOReceipts.size() > 0) mySTOReceipts.resize(mySTOReceipts.size()-1);
  return mySTOReceipts;
}

void CMPSTOList::getRecipients(const uint256 txid, string filterAddress, UniValue *recipientArray, uint64_t *total, uint64_t *numRecipients)
{
  if (!pdb) return;

  bool filter = true; //default
  bool filterByWallet = true; //default
  bool filterByAddress = false; //default

  if (filterAddress == "*") filter = false;
  if ((filterAddress != "") && (filterAddress != "*")) { filterByWallet = false; filterByAddress = true; }

  // iterate through SDB, dropping all records where key is not filterAddress (if filtering)
  int count = 0;

  // the fee is variable based on version of STO - provide number of recipients and allow calling function to work out fee
  *numRecipients = 0;

  Slice skey, svalue;
  Iterator* it = NewIterator();
  for(it->SeekToFirst(); it->Valid(); it->Next())
  {
      skey = it->key();
      string recipientAddress = skey.ToString();
      svalue = it->value();
      string strValue = svalue.ToString();
      // see if txid is in the data
      size_t txidMatch = strValue.find(txid.ToString());
      if(txidMatch!=std::string::npos)
      {
          ++*numRecipients;
          // the txid exists inside the data, this address was a recipient of this STO, check filter and add the details
          if(filter)
          {
              if( ( (filterByAddress) && (filterAddress == recipientAddress) ) || ( (filterByWallet) && (IsMyAddress(recipientAddress)) ) )
              { } else { continue; } // move on if no filter match (but counter still increased for fee)
          }
          std::vector<std::string> vstr;
          boost::split(vstr, strValue, boost::is_any_of(","), token_compress_on);
          for(uint32_t i = 0; i<vstr.size(); i++)
          {
              std::vector<std::string> svstr;
              boost::split(svstr, vstr[i], boost::is_any_of(":"), token_compress_on);
              if(4 == svstr.size())
              {
                  if(svstr[0] == txid.ToString())
                  {
                      //add data to array
                      uint64_t amount = 0;
                      uint64_t propertyId = 0;
                      try
                      {
                          amount = boost::lexical_cast<uint64_t>(svstr[3]);
                          propertyId = boost::lexical_cast<uint64_t>(svstr[2]);
                      } catch (const boost::bad_lexical_cast &e)
                      {
                          PrintToLog("DEBUG STO - error in converting values from leveldb\n");
                          delete it;
                          return; //(something went wrong)
                      }
                      UniValue recipient(UniValue::VOBJ);
                      recipient.push_back(Pair("address", recipientAddress));
                      if(isPropertyDivisible(propertyId))
                      {
                         recipient.push_back(Pair("amount", FormatDivisibleMP(amount)));
                      }
                      else
                      {
                         recipient.push_back(Pair("amount", FormatIndivisibleMP(amount)));
                      }
                      *total += amount;
                      recipientArray->push_back(recipient);
                      ++count;
                  }
              }
          }
      }
  }

  delete it;
  return;
}

bool CMPSTOList::exists(string address)
{
  if (!pdb) return false;

  string strValue;
  Status status = pdb->Get(readoptions, address, &strValue);

  if (!status.ok())
  {
    if (status.IsNotFound()) return false;
  }

  return true;
}

void CMPSTOList::recordSTOReceive(string address, const uint256 &txid, int nBlock, unsigned int propertyId, uint64_t amount)
{
  if (!pdb) return;

  bool addressExists = s_stolistdb->exists(address);
  if (addressExists)
  {
      //retrieve existing record
      std::vector<std::string> vstr;
      string strValue;
      Status status = pdb->Get(readoptions, address, &strValue);
      if (status.ok())
      {
          // add details to record
          // see if we are overwriting (check)
          size_t txidMatch = strValue.find(txid.ToString());
          if(txidMatch!=std::string::npos) PrintToLog("STODEBUG : Duplicating entry for %s : %s\n",address,txid.ToString());

          const string key = address;
          const string newValue = strprintf("%s:%d:%u:%lu,", txid.ToString(), nBlock, propertyId, amount);
          strValue += newValue;
          // write updated record
          Status status;
          if (pdb)
          {
              status = pdb->Put(writeoptions, key, strValue);
              PrintToLog("STODBDEBUG : %s(): %s, line %d, file: %s\n", __FUNCTION__, status.ToString(), __LINE__, __FILE__);
          }
      }
  }
  else
  {
      const string key = address;
      const string value = strprintf("%s:%d:%u:%lu,", txid.ToString(), nBlock, propertyId, amount);
      Status status;
      if (pdb)
      {
          status = pdb->Put(writeoptions, key, value);
          PrintToLog("STODBDEBUG : %s(): %s, line %d, file: %s\n", __FUNCTION__, status.ToString(), __LINE__, __FILE__);
      }
  }
}

void CMPSTOList::printAll()
{
  int count = 0;
  Slice skey, svalue;
  Iterator* it = NewIterator();

  for(it->SeekToFirst(); it->Valid(); it->Next())
  {
    skey = it->key();
    svalue = it->value();
    ++count;
    PrintToLog("entry #%8d= %s:%s\n", count, skey.ToString(), svalue.ToString());
  }

  delete it;
}

void CMPSTOList::printStats()
{
  PrintToLog("CMPSTOList stats: tWritten= %d , tRead= %d\n", nWritten, nRead);
}

/**
 * This function deletes records of STO receivers above/equal to a specific block from the STO database.
 *
 * Returns the number of records changed.
 */
int CMPSTOList::deleteAboveBlock(int blockNum)
{
  unsigned int n_found = 0;
  std::vector<std::string> vecSTORecords;
  leveldb::Iterator* it = NewIterator();
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
      std::string newValue;
      std::string oldValue = it->value().ToString();
      bool needsUpdate = false;
      boost::split(vecSTORecords, oldValue, boost::is_any_of(","), boost::token_compress_on);
      for (uint32_t i = 0; i<vecSTORecords.size(); i++) {
          std::vector<std::string> vecSTORecordFields;
          boost::split(vecSTORecordFields, vecSTORecords[i], boost::is_any_of(":"), boost::token_compress_on);
          if (4 != vecSTORecordFields.size()) continue;
          if (atoi(vecSTORecordFields[1]) < blockNum) {
              newValue += vecSTORecords[i].append(","); // STO before the reorg, add data back to new value string
          } else {
              needsUpdate = true;
          }
      }
      if (needsUpdate) { // rewrite record with existing key and new value
          ++n_found;
          leveldb::Status status = pdb->Put(writeoptions, it->key().ToString(), newValue);
          PrintToLog("DEBUG STO - rewriting STO data after reorg\n");
          PrintToLog("STODBDEBUG : %s(): %s, line %d, file: %s\n", __FUNCTION__, status.ToString(), __LINE__, __FILE__);
      }
  }

  PrintToLog("%s(%d); stodb updated records= %d\n", __FUNCTION__, blockNum, n_found);

  delete it;

  return (n_found);
}

// global wrapper, block numbers are inclusive, if ending_block is 0 top of the chain will be used
bool elysium::isMPinBlockRange(int starting_block, int ending_block, bool bDeleteFound)
{
  if (!p_txlistdb) return false;

  if (0 == ending_block) ending_block = GetHeight(); // will scan 'til the end

  return p_txlistdb->isMPinBlockRange(starting_block, ending_block, bDeleteFound);
}

// call it like so (variable # of parameters):
// int block = 0;
// ...
// uint64_t nNew = 0;
//
// if (getValidMPTX(txid, &block, &type, &nNew)) // if true -- the TX is a valid MP TX
//
bool elysium::getValidMPTX(const uint256 &txid, int *block, unsigned int *type, uint64_t *nAmended)
{
string result;
int validity = 0;

  if (elysium_debug_txdb) PrintToLog("%s()\n", __FUNCTION__);

  if (!p_txlistdb) return false;

  if (!p_txlistdb->getTX(txid, result)) return false;

  // parse the string returned, find the validity flag/bit & other parameters
  std::vector<std::string> vstr;
  boost::split(vstr, result, boost::is_any_of(":"), token_compress_on);

  if (elysium_debug_txdb) PrintToLog("%s() size=%lu : %s\n", __FUNCTION__, vstr.size(), result);

  if (1 <= vstr.size()) validity = atoi(vstr[0]);

  if (block)
  {
    if (2 <= vstr.size()) *block = atoi(vstr[1]);
    else *block = 0;
  }

  if (type)
  {
    if (3 <= vstr.size()) *type = atoi(vstr[2]);
    else *type = 0;
  }

  if (nAmended)
  {
    if (4 <= vstr.size()) *nAmended = boost::lexical_cast<boost::uint64_t>(vstr[3]);
    else nAmended = 0;
  }

  if (elysium_debug_txdb) p_txlistdb->printStats();

  if ((int)0 == validity) return false;

  return true;
}

int elysium_handler_block_begin(int nBlockPrev, CBlockIndex const * pBlockIndex)
{
    LOCK(cs_main);

    if (reorgRecoveryMode > 0) {
        reorgRecoveryMode = 0; // clear reorgRecovery here as this is likely re-entrant

        // Check if any freeze related transactions would be rolled back - if so wipe the state and startclean
        bool reorgContainsFreeze = p_txlistdb->CheckForFreezeTxs(pBlockIndex->nHeight);

        // NOTE: The blockNum parameter is inclusive, so deleteAboveBlock(1000) will delete records in block 1000 and above.
        p_txlistdb->isMPinBlockRange(pBlockIndex->nHeight, reorgRecoveryMaxHeight, true);
        s_stolistdb->deleteAboveBlock(pBlockIndex->nHeight);
		lelantusDb->DeleteAll(pBlockIndex->nHeight);
        reorgRecoveryMaxHeight = 0;

        nWaterlineBlock = ConsensusParams().GENESIS_BLOCK - 1;

        if (reorgContainsFreeze) {
            PrintToLog("Reorganization containing freeze related transactions detected, forcing a reparse...\n");
            clear_all_state(); // unable to reorg freezes safely, clear state and reparse
        } else {
            int best_state_block = load_most_relevant_state();
            if (best_state_block < 0) {
                // unable to recover easily, remove stale stale state bits and reparse from the beginning.
                clear_all_state();
            } else {
                nWaterlineBlock = best_state_block;
            }
        }

        // clear the global wallet property list, perform a forced wallet update and tell the UI that state is no longer valid, and UI views need to be reinit
        global_wallet_property_list.clear();
        CheckWalletUpdate(true);
        uiInterface.ElysiumStateInvalidated();

        if (nWaterlineBlock < nBlockPrev) {
            // scan from the block after the best active block to catch up to the active chain
            elysium_initial_scan(nWaterlineBlock + 1);
        }
    }

    // handle any features that go live with this block
    CheckLiveActivations(pBlockIndex->nHeight);

    return 0;
}

// called once per block, after the block has been processed
// TODO: consolidate into *handler_block_begin() << need to adjust Accept expiry check.............
// it performs cleanup and other functions
int elysium_handler_block_end(int nBlockNow, CBlockIndex const * pBlockIndex,
        unsigned int countMP)
{
    LOCK(cs_main);

    lelantusDb->CommitCoins();

    if (!elysiumInitialized) {
        elysium_init();
    }

    // check the alert status, do we need to do anything else here?
    CheckExpiredAlerts(nBlockNow, pBlockIndex->GetBlockTime());

    // check that pending transactions are still in the mempool
    PendingCheck();

    // transactions were found in the block, signal the UI accordingly
    if (countMP > 0) CheckWalletUpdate(true);

    // calculate and print a consensus hash if required
    if (ShouldConsensusHashBlock(nBlockNow)) {
        uint256 consensusHash = GetConsensusHash();
        PrintToLog("Consensus hash for block %d: %s\n", nBlockNow, consensusHash.GetHex());
    }
	
    // request checkpoint verification
    bool checkpointValid = VerifyCheckpoint(nBlockNow, pBlockIndex->GetBlockHash());

    if (!checkpointValid) {
        // failed checkpoint, can't be trusted to provide valid data - shutdown client
        const std::string& msg = strprintf("Shutting down due to failed checkpoint for block %d (hash %s)\n", nBlockNow, pBlockIndex->GetBlockHash().GetHex());
        PrintToLog(msg);
        if (!GetBoolArg("-overrideforcedshutdown", false)) {
            boost::filesystem::path persistPath = GetDataDir() / "MP_persist";
            if (boost::filesystem::exists(persistPath)) boost::filesystem::remove_all(persistPath); // prevent the node being restarted without a reparse after forced shutdown
            AbortNode(msg, msg);
        }
    } else {		
        // save out the state after this block
        if (writePersistence(nBlockNow)) {
            elysium_save_state(pBlockIndex);
        }
    }

    return 0;
}

int elysium_handler_disc_begin(int nBlockNow, CBlockIndex const * pBlockIndex)
{
    LOCK(cs_main);

    reorgRecoveryMode = 1;
    reorgRecoveryMaxHeight = (pBlockIndex->nHeight > reorgRecoveryMaxHeight) ? pBlockIndex->nHeight: reorgRecoveryMaxHeight;
    return 0;
}

int elysium_handler_disc_end(int nBlockNow, CBlockIndex const * pBlockIndex)
{
    return 0;
}
