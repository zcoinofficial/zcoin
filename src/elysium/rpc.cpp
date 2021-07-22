/**
 * @file rpc.cpp
 *
 * This file contains RPC calls for data retrieval.
 */

#include "rpc.h"

#include "activation.h"
#include "consensushash.h"
#include "convert.h"
#include "errors.h"

#include "fetchwallettx.h"
#include "log.h"
#include "notifications.h"
#include "elysium.h"
#include "rpcrequirements.h"
#include "rpctx.h"
#include "rpctxobject.h"
#include "rpcvalues.h"
#include "rules.h"
#include "sp.h"
#include "sto.h"
#include "tally.h"
#include "tx.h"
#include "utilsbitcoin.h"
#include "version.h"
#include "wallet.h"
#include "wallettxs.h"

#include "lelantusutils.h"

#ifdef ENABLE_WALLET
#include "wallet.h"
#endif

#include "../amount.h"
#include "../chainparams.h"
#include "../init.h"
#include "../validation.h"
#include "../primitives/block.h"
#include "../primitives/transaction.h"
#include "../rpc/server.h"
#include "../tinyformat.h"
#include "../txmempool.h"
#include "../uint256.h"
#include "../utilstrencodings.h"
#ifdef ENABLE_WALLET
#include "../wallet/wallet.h"
#endif

#include <univalue.h>

#include <map>
#include <stdexcept>
#include <string>
#include <utility>

#include <inttypes.h>

using std::runtime_error;
using namespace elysium;

namespace {

#ifdef ENABLE_WALLET
UniValue LelantusMintToJson(const LelantusMint& mint, bool verbose)
{
    // Load property info.
    CMPSPInfo::Entry info;

    {
        LOCK(cs_main);

        if (!_my_sps->getSP(mint.property, info)) {
            throw std::invalid_argument("property " + std::to_string(mint.property) + " is not valid");
        }
    }

    auto value = mint.amount;

    // Construct JSON.
    UniValue json(UniValue::VOBJ);

    json.push_back(Pair("propertyid", static_cast<uint64_t>(mint.property)));

    if (info.isDivisible()) {
        json.push_back(Pair("value", FormatDivisibleMP(value)));
    } else {
        json.push_back(Pair("value", FormatIndivisibleMP(value)));
    }

    if (verbose/* && mint.chainState.block >= 0*/) {
        json.push_back(Pair("block", mint.chainState.block));
        json.push_back(Pair("group", static_cast<uint64_t>(mint.chainState.group)));
        json.push_back(Pair("index", mint.chainState.index));
    }

    return json;
}

template<class It>
UniValue LelantusMintsToJson(It begin, It end, bool verbose = false)
{
    UniValue json(UniValue::VARR);

    for (auto it = begin; it != end; it++) {
        json.push_back(LelantusMintToJson(*it, verbose));
    }

    return json;
}
#endif

}

/**
 * Throws a JSONRPCError, depending on error code.
 */
void PopulateFailure(int error)
{
    switch (error) {
        case MP_TX_NOT_FOUND:
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
        case MP_TX_UNCONFIRMED:
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unconfirmed transactions are not supported");
        case MP_BLOCK_NOT_IN_CHAIN:
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not part of the active chain");
        case MP_INVALID_TX_IN_DB_FOUND:
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Potential database corruption: Invalid transaction found");
        case MP_TX_IS_NOT_ELYSIUM_PROTOCOL:
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Not a Elysium Protocol transaction");
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR, "Generic transaction population failure");
}

void PropertyToJSON(const CMPSPInfo::Entry& sProperty, UniValue& property_obj)
{
    property_obj.push_back(Pair("name", sProperty.name));
    property_obj.push_back(Pair("category", sProperty.category));
    property_obj.push_back(Pair("subcategory", sProperty.subcategory));
    property_obj.push_back(Pair("data", sProperty.data));
    property_obj.push_back(Pair("url", sProperty.url));
    property_obj.push_back(Pair("divisible", sProperty.isDivisible()));
}

bool BalanceToJSON(const std::string& address, uint32_t property, UniValue& balance_obj, bool divisible)
{
    // confirmed balance minus unconfirmed, spent amounts
    int64_t nAvailable = getUserAvailableMPbalance(address, property);

    int64_t nReserved = 0;

    int64_t nFrozen = getUserFrozenMPbalance(address, property);

    if (divisible) {
        balance_obj.push_back(Pair("balance", FormatDivisibleMP(nAvailable)));
        balance_obj.push_back(Pair("reserved", FormatDivisibleMP(nReserved)));
        if (nFrozen != 0) balance_obj.push_back(Pair("frozen", FormatDivisibleMP(nFrozen)));
    } else {
        balance_obj.push_back(Pair("balance", FormatIndivisibleMP(nAvailable)));
        balance_obj.push_back(Pair("reserved", FormatIndivisibleMP(nReserved)));
        if (nFrozen != 0) balance_obj.push_back(Pair("frozen", FormatIndivisibleMP(nFrozen)));
    }

    if (nAvailable == 0 && nReserved == 0) {
        return false;
    } else {
        return true;
    }
}

// obtain the payload for a transaction
UniValue elysium_getpayload(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "elysium_getpayload \"txid\"\n"
            "\nGet the payload for an Elysium transaction.\n"
            "\nArguments:\n"
            "1. txid                 (string, required) the hash of the transaction to retrieve payload\n"
            "\nResult:\n"
            "{\n"
            "  \"payload\" : \"payloadmessage\",       (string) the decoded Elysium payload message\n"
            "  \"payloadsize\" : n                     (number) the size of the payload\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_getpayload", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("elysium_getpayload", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    uint256 txid = ParseHashV(request.params[0], "txid");

    CTransactionRef tx;
    uint256 blockHash;
    if (!GetTransaction(txid, tx, Params().GetConsensus(), blockHash, true)) {
        PopulateFailure(MP_TX_NOT_FOUND);
    }

    int blockTime = 0;
    int blockHeight = GetHeight();
    if (!blockHash.IsNull()) {
        CBlockIndex* pBlockIndex = GetBlockIndex(blockHash);
        if (NULL != pBlockIndex) {
            blockTime = pBlockIndex->nTime;
            blockHeight = pBlockIndex->nHeight;
        }
    }

    CMPTransaction mp_obj;
    int parseRC = ParseTransaction(*tx, blockHeight, 0, mp_obj, blockTime);
    if (parseRC < 0) PopulateFailure(MP_TX_IS_NOT_ELYSIUM_PROTOCOL);

    auto& payload = mp_obj.getRaw();
    UniValue payloadObj(UniValue::VOBJ);
    payloadObj.push_back(Pair("payload", HexStr(payload)));
    payloadObj.push_back(Pair("payloadsize", int64_t(payload.size())));
    return payloadObj;
}

// determine whether to automatically commit transactions
UniValue elysium_setautocommit(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "elysium_setautocommit flag\n"
            "\nSets the global flag that determines whether transactions are automatically committed and broadcast.\n"
            "\nArguments:\n"
            "1. flag                 (boolean, required) the flag\n"
            "\nResult:\n"
            "true|false              (boolean) the updated flag status\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_setautocommit", "false")
            + HelpExampleRpc("elysium_setautocommit", "false")
        );

    LOCK(cs_main);

    autoCommit = request.params[0].get_bool();
    return autoCommit;
}

// display the tally map & the offer/accept list(s)
UniValue elysiumrpc(const JSONRPCRequest& request)
{
    int extra = 0;
    int extra2 = 0, extra3 = 0;

    if (request.fHelp || request.params.size() > 3)
        throw runtime_error(
            "elysiumrpc\n"
            "\nReturns the number of blocks in the longest block chain.\n"
            "\nResult:\n"
            "n    (number) the current block count\n"
            "\nExamples:\n"
            + HelpExampleCli("elysiumrpc", "")
            + HelpExampleRpc("elysiumrpc", "")
        );

    if (0 < request.params.size()) extra = atoi(request.params[0].get_str());
    if (1 < request.params.size()) extra2 = atoi(request.params[1].get_str());
    if (2 < request.params.size()) extra3 = atoi(request.params[2].get_str());

    PrintToLog("%s(extra=%d,extra2=%d,extra3=%d)\n", __FUNCTION__, extra, extra2, extra3);

    bool bDivisible = isPropertyDivisible(extra2);

    // various extra tests
    switch (extra) {
        case 0:
        {
            LOCK(cs_main);
            int64_t total = 0;
            // display all balances
            for (std::unordered_map<std::string, CMPTally>::iterator my_it = mp_tally_map.begin(); my_it != mp_tally_map.end(); ++my_it) {
                PrintToLog("%34s => ", my_it->first);
                total += (my_it->second).print(extra2, bDivisible);
            }
            PrintToLog("total for property %d  = %X is %s\n", extra2, extra2, FormatDivisibleMP(total));
            break;
        }
        case 1:
        {
            LOCK(cs_main);
            // display the whole CMPTxList (leveldb)
            p_txlistdb->printAll();
            p_txlistdb->printStats();
            break;
        }
        case 2:
        {
            LOCK(cs_main);
            // display smart properties
            _my_sps->printAll();
            break;
        }
        case 3:
        {
            LOCK(cs_main);
            uint32_t id = 0;
            // for each address display all currencies it holds
            for (std::unordered_map<std::string, CMPTally>::iterator my_it = mp_tally_map.begin(); my_it != mp_tally_map.end(); ++my_it) {
                PrintToLog("%34s => ", my_it->first);
                (my_it->second).print(extra2);
                (my_it->second).init();
                while (0 != (id = (my_it->second).next())) {
                    PrintToLog("Id: %u=0x%X ", id, id);
                }
                PrintToLog("\n");
            }
            break;
        }
        case 4:
        {
            LOCK(cs_main);
            PrintToLog("isMPinBlockRange(%d,%d)=%s\n", extra2, extra3, isMPinBlockRange(extra2, extra3, false) ? "YES" : "NO");
            break;
        }
        case 5:
        {
            LOCK(cs_main);
            // display the STO receive list
            s_stolistdb->printAll();
            s_stolistdb->printStats();
            break;
        }
        case 6:
        {
            PrintToLog("Locking cs_main for %d milliseconds..\n", extra2);
            LOCK(cs_main);
            MilliSleep(extra2);
            PrintToLog("Unlocking cs_main now\n");
            break;
        }
#ifdef ENABLE_WALLET
        case 7:
        {
            PrintToLog("Locking pwalletMain->cs_wallet for %d milliseconds..\n", extra2);
            LOCK(pwalletMain->cs_wallet);
            MilliSleep(extra2);
            PrintToLog("Unlocking pwalletMain->cs_wallet now\n");
            break;
        }
#endif       
        default:
            break;
    }

    return GetHeight();
}

// display an MP balance via RPC
UniValue elysium_getbalance(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "elysium_getbalance \"address\" propertyid\n"
            "\nReturns the token balance for a given address and property.\n"
            "\nArguments:\n"
            "1. address              (string, required) the address\n"
            "2. propertyid           (number, required) the property identifier\n"
            "\nResult:\n"
            "{\n"
            "  \"balance\" : \"n.nnnnnnnn\",   (string) the available balance of the address\n"
            "  \"reserved\" : \"n.nnnnnnnn\"   (string) the amount reserved by sell offers and accepts\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_getbalance", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\" 1")
            + HelpExampleRpc("elysium_getbalance", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\", 1")
        );

    std::string address = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);

    RequireExistingProperty(propertyId);

    UniValue balanceObj(UniValue::VOBJ);
    BalanceToJSON(address, propertyId, balanceObj, isPropertyDivisible(propertyId));

    return balanceObj;
}

UniValue elysium_getallbalancesforid(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "elysium_getallbalancesforid propertyid\n"
            "\nReturns a list of token balances for a given currency or property identifier.\n"
            "\nArguments:\n"
            "1. propertyid           (number, required) the property identifier\n"
            "\nResult:\n"
            "[                           (array of JSON objects)\n"
            "  {\n"
            "    \"address\" : \"address\",      (string) the address\n"
            "    \"balance\" : \"n.nnnnnnnn\",   (string) the available balance of the address\n"
            "    \"reserved\" : \"n.nnnnnnnn\"   (string) the amount reserved by sell offers and accepts\n"
            "  },\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_getallbalancesforid", "1")
            + HelpExampleRpc("elysium_getallbalancesforid", "1")
        );

    uint32_t propertyId = ParsePropertyId(request.params[0]);

    RequireExistingProperty(propertyId);

    UniValue response(UniValue::VARR);
    bool isDivisible = isPropertyDivisible(propertyId); // we want to check this BEFORE the loop

    LOCK(cs_main);

    for (std::unordered_map<std::string, CMPTally>::iterator it = mp_tally_map.begin(); it != mp_tally_map.end(); ++it) {
        uint32_t id = 0;
        bool includeAddress = false;
        std::string address = it->first;
        (it->second).init();
        while (0 != (id = (it->second).next())) {
            if (id == propertyId) {
                includeAddress = true;
                break;
            }
        }
        if (!includeAddress) {
            continue; // ignore this address, has never transacted in this propertyId
        }
        UniValue balanceObj(UniValue::VOBJ);
        balanceObj.push_back(Pair("address", address));
        bool nonEmptyBalance = BalanceToJSON(address, propertyId, balanceObj, isDivisible);

        if (nonEmptyBalance) {
            response.push_back(balanceObj);
        }
    }

    return response;
}

UniValue elysium_getallbalancesforaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "elysium_getallbalancesforaddress \"address\"\n"
            "\nReturns a list of all token balances for a given address.\n"
            "\nArguments:\n"
            "1. address              (string, required) the address\n"
            "\nResult:\n"
            "[                           (array of JSON objects)\n"
            "  {\n"
            "    \"propertyid\" : n,           (number) the property identifier\n"
            "    \"balance\" : \"n.nnnnnnnn\",   (string) the available balance of the address\n"
            "    \"reserved\" : \"n.nnnnnnnn\"   (string) the amount reserved by sell offers and accepts\n"
            "  },\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_getallbalancesforaddress", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\"")
            + HelpExampleRpc("elysium_getallbalancesforaddress", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\"")
        );

    std::string address = ParseAddress(request.params[0]);

    UniValue response(UniValue::VARR);

    LOCK(cs_main);

    CMPTally* addressTally = getTally(address);

    if (NULL == addressTally) { // addressTally object does not exist
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Address not found");
    }

    addressTally->init();

    uint32_t propertyId = 0;
    while (0 != (propertyId = addressTally->next())) {
        UniValue balanceObj(UniValue::VOBJ);
        balanceObj.push_back(Pair("propertyid", (uint64_t) propertyId));
        bool nonEmptyBalance = BalanceToJSON(address, propertyId, balanceObj, isPropertyDivisible(propertyId));

        if (nonEmptyBalance) {
            response.push_back(balanceObj);
        }
    }

    return response;
}

UniValue elysium_getproperty(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "elysium_getproperty propertyid\n"
            "\nReturns details for about the tokens or smart property to lookup.\n"
            "\nArguments:\n"
            "1. propertyid           (number, required) the identifier of the tokens or property\n"
            "\nResult:\n"
            "{\n"
            "  \"propertyid\" : n,                (number) the identifier\n"
            "  \"name\" : \"name\",                 (string) the name of the tokens\n"
            "  \"category\" : \"category\",         (string) the category used for the tokens\n"
            "  \"subcategory\" : \"subcategory\",   (string) the subcategory used for the tokens\n"
            "  \"data\" : \"information\",          (string) additional information or a description\n"
            "  \"url\" : \"uri\",                   (string) an URI, for example pointing to a website\n"
            "  \"divisible\" : true|false,        (boolean) whether the tokens are divisible\n"
            "  \"issuer\" : \"address\",            (string) the Firo address of the issuer on record\n"
            "  \"creationtxid\" : \"hash\",         (string) the hex-encoded creation transaction hash\n"
            "  \"fixedissuance\" : true|false,    (boolean) whether the token supply is fixed\n"
            "  \"managedissuance\" : true|false,  (boolean) whether the token supply is managed\n"
            "  \"totaltokens\" : \"n.nnnnnnnn\",    (string) the total number of tokens in existence\n"
            "  \"sigmastatus\" : \"status\",        (string) the sigma status of the tokens\n"
            "  \"denominations\": [               (array of JSON objects) a list of sigma denominations\n"
            "    {\n"
            "      \"id\" : n                     (number) the identifier of the denomination\n"
            "      \"value\" : \"n.nnnnnnnn\"       (string) the value of the denomination\n"
            "    },\n"
            "    ...\n"
            "  ],\n"
            "  \"lelantusstatus\" : \"status\",     (string) the lelantus status of the tokens\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_getproperty", "3")
            + HelpExampleRpc("elysium_getproperty", "3")
        );

    uint32_t propertyId = ParsePropertyId(request.params[0]);

    RequireExistingProperty(propertyId);

    CMPSPInfo::Entry sp;
    {
        LOCK(cs_main);
        if (!_my_sps->getSP(propertyId, sp)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Property identifier does not exist");
        }
    }
    int64_t nTotalTokens = getTotalTokens(propertyId);
    std::string strCreationHash = sp.txid.GetHex();
    std::string strTotalTokens = FormatMP(propertyId, nTotalTokens);

    UniValue response(UniValue::VOBJ);
    response.push_back(Pair("propertyid", (uint64_t) propertyId));
    PropertyToJSON(sp, response); // name, category, subcategory, data, url, divisible
    response.push_back(Pair("issuer", sp.issuer));
    response.push_back(Pair("creationtxid", strCreationHash));
    response.push_back(Pair("fixedissuance", sp.fixed));
    response.push_back(Pair("managedissuance", sp.manual));
    if (sp.manual) {
        int currentBlock = GetHeight();
        LOCK(cs_main);
        response.push_back(Pair("freezingenabled", isFreezingEnabled(propertyId, currentBlock)));
    }
    response.push_back(Pair("totaltokens", strTotalTokens));

    UniValue denominations(UniValue::VARR);
    for (size_t i = 0; i < sp.denominations.size(); i++) {
        UniValue denomination(UniValue::VOBJ);
        denomination.push_back(Pair("id", int64_t(i)));
        denomination.push_back(Pair("value", FormatMP(propertyId, sp.denominations[i])));
        denominations.push_back(denomination);
    }

    response.push_back(Pair("denominations", denominations));

    try {
        response.push_back(Pair("lelantusstatus", std::to_string(sp.lelantusStatus)));
    } catch (const std::invalid_argument& e) {
        // status is invalid
        throw JSONRPCError(RPC_INTERNAL_ERROR, e.what());
    }

    return response;
}

UniValue elysium_listproperties(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw runtime_error(
            "elysium_listproperties\n"
            "\nLists all tokens or smart properties.\n"
            "\nResult:\n"
            "[                                (array of JSON objects)\n"
            "  {\n"
            "    \"propertyid\" : n,                (number) the identifier of the tokens\n"
            "    \"name\" : \"name\",                 (string) the name of the tokens\n"
            "    \"category\" : \"category\",         (string) the category used for the tokens\n"
            "    \"subcategory\" : \"subcategory\",   (string) the subcategory used for the tokens\n"
            "    \"data\" : \"information\",          (string) additional information or a description\n"
            "    \"url\" : \"uri\",                   (string) an URI, for example pointing to a website\n"
            "    \"divisible\" : true|false         (boolean) whether the tokens are divisible\n"
            "  },\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_listproperties", "")
            + HelpExampleRpc("elysium_listproperties", "")
        );

    UniValue response(UniValue::VARR);

    LOCK(cs_main);

    uint32_t nextSPID = _my_sps->peekNextSPID(1);
    for (uint32_t propertyId = 1; propertyId < nextSPID; propertyId++) {
        CMPSPInfo::Entry sp;
        if (_my_sps->getSP(propertyId, sp)) {
            UniValue propertyObj(UniValue::VOBJ);
            propertyObj.push_back(Pair("propertyid", (uint64_t) propertyId));
            PropertyToJSON(sp, propertyObj); // name, category, subcategory, data, url, divisible

            response.push_back(propertyObj);
        }
    }

    uint32_t nextTestSPID = _my_sps->peekNextSPID(2);
    for (uint32_t propertyId = TEST_ECO_PROPERTY_1; propertyId < nextTestSPID; propertyId++) {
        CMPSPInfo::Entry sp;
        if (_my_sps->getSP(propertyId, sp)) {
            UniValue propertyObj(UniValue::VOBJ);
            propertyObj.push_back(Pair("propertyid", (uint64_t) propertyId));
            PropertyToJSON(sp, propertyObj); // name, category, subcategory, data, url, divisible

            response.push_back(propertyObj);
        }
    }

    return response;
}

UniValue elysium_getgrants(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "elysium_getgrants propertyid\n"
            "\nReturns information about granted and revoked units of managed tokens.\n"
            "\nArguments:\n"
            "1. propertyid           (number, required) the identifier of the managed tokens to lookup\n"
            "\nResult:\n"
            "{\n"
            "  \"propertyid\" : n,               (number) the identifier of the managed tokens\n"
            "  \"name\" : \"name\",                (string) the name of the tokens\n"
            "  \"issuer\" : \"address\",           (string) the Firo address of the issuer on record\n"
            "  \"creationtxid\" : \"hash\",        (string) the hex-encoded creation transaction hash\n"
            "  \"totaltokens\" : \"n.nnnnnnnn\",   (string) the total number of tokens in existence\n"
            "  \"issuances\": [                  (array of JSON objects) a list of the granted and revoked tokens\n"
            "    {\n"
            "      \"txid\" : \"hash\",                (string) the hash of the transaction that granted tokens\n"
            "      \"grant\" : \"n.nnnnnnnn\"          (string) the number of tokens granted by this transaction\n"
            "    },\n"
            "    {\n"
            "      \"txid\" : \"hash\",                (string) the hash of the transaction that revoked tokens\n"
            "      \"grant\" : \"n.nnnnnnnn\"          (string) the number of tokens revoked by this transaction\n"
            "    },\n"
            "    ...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_getgrants", "31")
            + HelpExampleRpc("elysium_getgrants", "31")
        );

    uint32_t propertyId = ParsePropertyId(request.params[0]);

    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);

    CMPSPInfo::Entry sp;
    {
        LOCK(cs_main);
        if (false == _my_sps->getSP(propertyId, sp)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Property identifier does not exist");
        }
    }
    UniValue response(UniValue::VOBJ);
    const uint256& creationHash = sp.txid;
    int64_t totalTokens = getTotalTokens(propertyId);

    // TODO: sort by height?

    UniValue issuancetxs(UniValue::VARR);
    std::map<uint256, std::vector<int64_t> >::const_iterator it;
    for (it = sp.historicalData.begin(); it != sp.historicalData.end(); it++) {
        const std::string& txid = it->first.GetHex();
        int64_t grantedTokens = it->second.at(0);
        int64_t revokedTokens = it->second.at(1);

        if (grantedTokens > 0) {
            UniValue granttx(UniValue::VOBJ);
            granttx.push_back(Pair("txid", txid));
            granttx.push_back(Pair("grant", FormatMP(propertyId, grantedTokens)));
            issuancetxs.push_back(granttx);
        }

        if (revokedTokens > 0) {
            UniValue revoketx(UniValue::VOBJ);
            revoketx.push_back(Pair("txid", txid));
            revoketx.push_back(Pair("revoke", FormatMP(propertyId, revokedTokens)));
            issuancetxs.push_back(revoketx);
        }
    }

    response.push_back(Pair("propertyid", (uint64_t) propertyId));
    response.push_back(Pair("name", sp.name));
    response.push_back(Pair("issuer", sp.issuer));
    response.push_back(Pair("creationtxid", creationHash.GetHex()));
    response.push_back(Pair("totaltokens", FormatMP(propertyId, totalTokens)));
    response.push_back(Pair("issuances", issuancetxs));

    return response;
}

UniValue elysium_listblocktransactions(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "elysium_listblocktransactions index\n"
            "\nLists all Elysium transactions in a block.\n"
            "\nArguments:\n"
            "1. index                (number, required) the block height or block index\n"
            "\nResult:\n"
            "[                       (array of string)\n"
            "  \"hash\",                 (string) the hash of the transaction\n"
            "  ...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_listblocktransactions", "279007")
            + HelpExampleRpc("elysium_listblocktransactions", "279007")
        );

    int blockHeight = request.params[0].get_int();

    RequireHeightInChain(blockHeight);

    // next let's obtain the block for this height
    CBlock block;
    {
        LOCK(cs_main);
        CBlockIndex* pBlockIndex = chainActive[blockHeight];

        if (!ReadBlockFromDisk(block, pBlockIndex, Params().GetConsensus())) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to read block from disk");
        }
    }

    UniValue response(UniValue::VARR);

    // now we want to loop through each of the transactions in the block and run against CMPTxList::exists
    // those that return positive add to our response array

    LOCK(cs_main);

    BOOST_FOREACH(CTransactionRef tx, block.vtx) {
        if (p_txlistdb->exists(tx->GetHash())) {
            // later we can add a verbose flag to decode here, but for now callers can send returned txids into gettransaction_MP
            // add the txid into the response as it's an MP transaction
            response.push_back(tx->GetHash().GetHex());
        }
    }

    return response;
}

UniValue elysium_gettransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "elysium_gettransaction \"txid\"\n"
            "\nGet detailed information about an Elysium transaction.\n"
            "\nArguments:\n"
            "1. txid                 (string, required) the hash of the transaction to lookup\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"hash\",                  (string) the hex-encoded hash of the transaction\n"
            "  \"sendingaddress\" : \"address\",     (string) the Firo address of the sender\n"
            "  \"referenceaddress\" : \"address\",   (string) a Firo address used as reference (if any)\n"
            "  \"ismine\" : true|false,            (boolean) whether the transaction involes an address in the wallet\n"
            "  \"confirmations\" : nnnnnnnnnn,     (number) the number of transaction confirmations\n"
            "  \"fee\" : \"n.nnnnnnnn\",             (string) the transaction fee in firos\n"
            "  \"blocktime\" : nnnnnnnnnn,         (number) the timestamp of the block that contains the transaction\n"
            "  \"valid\" : true|false,             (boolean) whether the transaction is valid\n"
            "  \"invalidreason\" : \"reason\",     (string) if a transaction is invalid, the reason \n"
            "  \"version\" : n,                    (number) the transaction version\n"
            "  \"type_int\" : n,                   (number) the transaction type as number\n"
            "  \"type\" : \"type\",                  (string) the transaction type as string\n"
            "  [...]                             (mixed) other transaction type specific properties\n"
            "}\n"
            "\nbExamples:\n"
            + HelpExampleCli("elysium_gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("elysium_gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    uint256 hash = ParseHashV(request.params[0], "txid");

    UniValue txobj(UniValue::VOBJ);
    int populateResult = populateRPCTransactionObject(hash, txobj);
    if (populateResult != 0) PopulateFailure(populateResult);

    return txobj;
}

UniValue elysium_listtransactions(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 5)
        throw runtime_error(
            "elysium_listtransactions ( \"address\" count skip startblock endblock )\n"
            "\nList wallet transactions, optionally filtered by an address and block boundaries.\n"
            "\nArguments:\n"
            "1. address              (string, optional) address filter (default: \"*\")\n"
            "2. count                (number, optional) show at most n transactions (default: 10)\n"
            "3. skip                 (number, optional) skip the first n transactions (default: 0)\n"
            "4. startblock           (number, optional) first block to begin the search (default: 0)\n"
            "5. endblock             (number, optional) last block to include in the search (default: 999999)\n"
            "\nResult:\n"
            "[                                 (array of JSON objects)\n"
            "  {\n"
            "    \"txid\" : \"hash\",                  (string) the hex-encoded hash of the transaction\n"
            "    \"sendingaddress\" : \"address\",     (string) the Firo address of the sender\n"
            "    \"referenceaddress\" : \"address\",   (string) a Firo address used as reference (if any)\n"
            "    \"ismine\" : true|false,            (boolean) whether the transaction involes an address in the wallet\n"
            "    \"confirmations\" : nnnnnnnnnn,     (number) the number of transaction confirmations\n"
            "    \"fee\" : \"n.nnnnnnnn\",             (string) the transaction fee in firos\n"
            "    \"blocktime\" : nnnnnnnnnn,         (number) the timestamp of the block that contains the transaction\n"
            "    \"valid\" : true|false,             (boolean) whether the transaction is valid\n"
            "    \"version\" : n,                    (number) the transaction version\n"
            "    \"type_int\" : n,                   (number) the transaction type as number\n"
            "    \"type\" : \"type\",                  (string) the transaction type as string\n"
            "    [...]                             (mixed) other transaction type specific properties\n"
            "  },\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_listtransactions", "")
            + HelpExampleRpc("elysium_listtransactions", "")
        );

    // obtains parameters - default all wallet addresses & last 10 transactions
    std::string addressParam;
    if (request.params.size() > 0) {
        if (("*" != request.params[0].get_str()) && ("" != request.params[0].get_str())) addressParam = request.params[0].get_str();
    }
    int64_t nCount = 10;
    if (request.params.size() > 1) nCount = request.params[1].get_int64();
    if (nCount < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    int64_t nFrom = 0;
    if (request.params.size() > 2) nFrom = request.params[2].get_int64();
    if (nFrom < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");
    int64_t nStartBlock = 0;
    if (request.params.size() > 3) nStartBlock = request.params[3].get_int64();
    if (nStartBlock < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative start block");
    int64_t nEndBlock = 999999;
    if (request.params.size() > 4) nEndBlock = request.params[4].get_int64();
    if (nEndBlock < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative end block");

    // obtain a sorted list of Elysium layer wallet transactions (including STO receipts and pending)
    std::map<std::string,uint256> walletTransactions = FetchWalletElysiumTransactions(nFrom+nCount, nStartBlock, nEndBlock);

    // reverse iterate over (now ordered) transactions and populate RPC objects for each one
    UniValue response(UniValue::VARR);
    for (std::map<std::string,uint256>::reverse_iterator it = walletTransactions.rbegin(); it != walletTransactions.rend(); it++) {
        uint256 txHash = it->second;
        UniValue txobj(UniValue::VOBJ);
        int populateResult = populateRPCTransactionObject(txHash, txobj, addressParam);
        if (0 == populateResult) response.push_back(txobj);
    }

    // TODO: reenable cutting!
/*
    // cut on nFrom and nCount
    if (nFrom > (int)response.size()) nFrom = response.size();
    if ((nFrom + nCount) > (int)response.size()) nCount = response.size() - nFrom;
    UniValue::iterator first = response.begin();
    std::advance(first, nFrom);
    UniValue::iterator last = response.begin();
    std::advance(last, nFrom+nCount);
    if (last != response.end()) response.erase(last, response.end());
    if (first != response.begin()) response.erase(response.begin(), first);
    std::reverse(response.begin(), response.end());
*/
    return response;
}

#ifdef ENABLE_WALLET
UniValue elysium_listlelantusmints(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            "elysium_listlelantusmints ( propertyid verbose )\n"
            "\nList all non-pending unused lelantus mints in the wallet, optionally filtered by property.\n"
            "\nArguments:\n"
            "1. propertyid           (number, optional) show only mints that belonged to this property\n"
            "2. verbose              (boolean, optional) show additional information (default: false)\n"
            "\nResult:\n"
            "[                       (array of JSON objects)\n"
            "  {\n"
            "    \"propertyid\" : n,        (number) property identifier that mint belonged to\n"
            "    \"value\" : \"n.nnnnnnnn\" (string) value of the mint\n"
            "    \"block\" : n              (number) the block number that mint got mined (if verbose enabled)\n"
            "    \"group\" : n              (number) group identifier that mint belonged to (if verbose enabled)\n"
            "    \"index\" : n              (number) index of the mint in the group (if verbose enabled)\n"
            "  },\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_listlelantusmints", "")
            + HelpExampleRpc("elysium_listlelantusmints", "")
        );
    }

    // Get parameters.
    boost::optional<PropertyId> property;
    bool verbose = false;

    if (request.params.size() > 0) {
        property = ParsePropertyId(request.params[0]);
        RequireExistingProperty(property.get());
    }

    if (request.params.size() > 1) {
        verbose = request.params[1].get_bool();
    }

    // Get mints that meet criteria.
    std::vector<LelantusMint> mints;

    wallet->ListLelantusMints(boost::make_function_output_iterator([&] (const std::pair<MintEntryId, LelantusMint>& m) {
        if (m.second.IsSpent() || !m.second.IsOnChain()) {
            return;
        }

        if (property && m.second.property != property.get()) {
            return;
        }

        mints.push_back(m.second);
    }));

    return LelantusMintsToJson(mints.begin(), mints.end(), verbose);
}

UniValue elysium_listpendinglelantusmints(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "elysium_listpendinglelantusmints\n"
            "\nList all pending sigma mints in the wallet.\n"
            "\nResult:\n"
            "[                       (array of JSON objects)\n"
            "  {\n"
            "    \"propertyid\" : n,        (number) property identifier that mint belonged to\n"
            "    \"value\" : \"n.nnnnnnnn\" (string) value of the mint\n"
            "  },\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_listpendinglelantusmints", "")
            + HelpExampleRpc("elysium_listpendinglelantusmints", "")
        );
    }

    std::vector<LelantusMint> mints;

    wallet->ListLelantusMints(boost::make_function_output_iterator([&] (const std::pair<MintEntryId, LelantusMint>& m) {
        if (m.second.IsOnChain()) {
            return;
        }

        mints.push_back(m.second);
    }));

    return LelantusMintsToJson(mints.begin(), mints.end());
}
#endif

UniValue elysium_listpendingtransactions(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
            "elysium_listpendingtransactions ( \"address\" )\n"
            "\nReturns a list of unconfirmed Elysium transactions, pending in the memory pool.\n"
            "\nAn optional filter can be provided to only include transactions which involve the given address.\n"
            "\nNote: the validity of pending transactions is uncertain, and the state of the memory pool may "
            "change at any moment. It is recommended to check transactions after confirmation, and pending "
            "transactions should be considered as invalid.\n"
            "\nArguments:\n"
            "1. address              (string, optional) address filter (default: \"\" for no filter)\n"
            "\nResult:\n"
            "[                                 (array of JSON objects)\n"
            "  {\n"
            "    \"txid\" : \"hash\",                  (string) the hex-encoded hash of the transaction\n"
            "    \"sendingaddress\" : \"address\",     (string) the Firo address of the sender\n"
            "    \"referenceaddress\" : \"address\",   (string) a Firo address used as reference (if any)\n"
            "    \"ismine\" : true|false,            (boolean) whether the transaction involes an address in the wallet\n"
            "    \"fee\" : \"n.nnnnnnnn\",             (string) the transaction fee in firos\n"
            "    \"version\" : n,                    (number) the transaction version\n"
            "    \"type_int\" : n,                   (number) the transaction type as number\n"
            "    \"type\" : \"type\",                  (string) the transaction type as string\n"
            "    [...]                             (mixed) other transaction type specific properties\n"
            "  },\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_listpendingtransactions", "")
            + HelpExampleRpc("elysium_listpendingtransactions", "")
        );

    std::string filterAddress;
    if (request.params.size() > 0) {
        filterAddress = ParseAddressOrEmpty(request.params[0]);
    }

    std::vector<uint256> vTxid;
    mempool.queryHashes(vTxid);

    UniValue result(UniValue::VARR);
    BOOST_FOREACH(const uint256& hash, vTxid) {
        UniValue txObj(UniValue::VOBJ);
        if (populateRPCTransactionObject(hash, txObj, filterAddress) == 0) {
            result.push_back(txObj);
        }
    }

    return result;
}

UniValue elysium_getinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "elysium_getinfo\n"
            "Returns various state information of the client and protocol.\n"
            "\nResult:\n"
            "{\n"
            "  \"elysiumversion_int\" : xxxxxxx,      (number) client version as integer\n"
            "  \"elysiumversion\" : \"x.x.x.x-xxx\",    (string) client version\n"
            "  \"firocoreversion\" : \"x.x.x\",        (string) Firo Core version\n"
            "  \"block\" : nnnnnn,                      (number) index of the last processed block\n"
            "  \"blocktime\" : nnnnnnnnnn,              (number) timestamp of the last processed block\n"
            "  \"blocktransactions\" : nnnn,            (number) Elysium transactions found in the last processed block\n"
            "  \"totaltransactions\" : nnnnnnnn,        (number) Elysium transactions processed in total\n"
            "  \"alerts\" : [                           (array of JSON objects) active protocol alert (if any)\n"
            "    {\n"
            "      \"alerttypeint\" : n,                    (number) alert type as integer\n"
            "      \"alerttype\" : \"xxx\",                   (string) alert type\n"
            "      \"alertexpiry\" : \"nnnnnnnnnn\",          (string) expiration criteria\n"
            "      \"alertmessage\" : \"xxx\"                 (string) information about the alert\n"
            "    },\n"
            "    ...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_getinfo", "")
            + HelpExampleRpc("elysium_getinfo", "")
        );

    UniValue infoResponse(UniValue::VOBJ);

    // provide the Elysium and Firo version
    infoResponse.push_back(Pair("elysiumversion_int", ELYSIUM_VERSION));
    infoResponse.push_back(Pair("elysiumversion", ElysiumVersion()));
    infoResponse.push_back(Pair("firocoreversion", FiroCoreVersion()));

    // provide the current block details
    int block = GetHeight();
    int64_t blockTime = GetLatestBlockTime();

    LOCK(cs_main);

    int blockMPTransactions = p_txlistdb->getMPTransactionCountBlock(block);
    int totalMPTransactions = p_txlistdb->getMPTransactionCountTotal();
    infoResponse.push_back(Pair("block", block));
    infoResponse.push_back(Pair("blocktime", blockTime));
    infoResponse.push_back(Pair("blocktransactions", blockMPTransactions));

    // provide the number of transactions parsed
    infoResponse.push_back(Pair("totaltransactions", totalMPTransactions));

    // handle alerts
    UniValue alerts(UniValue::VARR);
    std::vector<AlertData> elysiumAlerts = GetElysiumAlerts();
    for (std::vector<AlertData>::iterator it = elysiumAlerts.begin(); it != elysiumAlerts.end(); it++) {
        AlertData alert = *it;
        UniValue alertResponse(UniValue::VOBJ);
        std::string alertTypeStr;
        switch (alert.alert_type) {
            case 1: alertTypeStr = "alertexpiringbyblock";
            break;
            case 2: alertTypeStr = "alertexpiringbyblocktime";
            break;
            case 3: alertTypeStr = "alertexpiringbyclientversion";
            break;
            default: alertTypeStr = "error";
        }
        alertResponse.push_back(Pair("alerttypeint", alert.alert_type));
        alertResponse.push_back(Pair("alerttype", alertTypeStr));
        alertResponse.push_back(Pair("alertexpiry", FormatIndivisibleMP(alert.alert_expiry)));
        alertResponse.push_back(Pair("alertmessage", alert.alert_message));
        alerts.push_back(alertResponse);
    }
    infoResponse.push_back(Pair("alerts", alerts));

    return infoResponse;
}

UniValue elysium_getactivations(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "elysium_getactivations\n"
            "Returns pending and completed feature activations.\n"
            "\nResult:\n"
            "{\n"
            "  \"pendingactivations\": [       (array of JSON objects) a list of pending feature activations\n"
            "    {\n"
            "      \"featureid\" : n,              (number) the id of the feature\n"
            "      \"featurename\" : \"xxxxxxxx\",   (string) the name of the feature\n"
            "      \"activationblock\" : n,        (number) the block the feature will be activated\n"
            "      \"minimumversion\" : n          (number) the minimum client version needed to support this feature\n"
            "    },\n"
            "    ...\n"
            "  ]\n"
            "  \"completedactivations\": [     (array of JSON objects) a list of completed feature activations\n"
            "    {\n"
            "      \"featureid\" : n,              (number) the id of the feature\n"
            "      \"featurename\" : \"xxxxxxxx\",   (string) the name of the feature\n"
            "      \"activationblock\" : n,        (number) the block the feature will be activated\n"
            "      \"minimumversion\" : n          (number) the minimum client version needed to support this feature\n"
            "    },\n"
            "    ...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_getactivations", "")
            + HelpExampleRpc("elysium_getactivations", "")
        );

    UniValue response(UniValue::VOBJ);

    UniValue arrayPendingActivations(UniValue::VARR);
    std::vector<FeatureActivation> vecPendingActivations = GetPendingActivations();
    for (std::vector<FeatureActivation>::iterator it = vecPendingActivations.begin(); it != vecPendingActivations.end(); ++it) {
        UniValue actObj(UniValue::VOBJ);
        FeatureActivation pendingAct = *it;
        actObj.push_back(Pair("featureid", pendingAct.featureId));
        actObj.push_back(Pair("featurename", pendingAct.featureName));
        actObj.push_back(Pair("activationblock", pendingAct.activationBlock));
        actObj.push_back(Pair("minimumversion", (uint64_t)pendingAct.minClientVersion));
        arrayPendingActivations.push_back(actObj);
    }

    UniValue arrayCompletedActivations(UniValue::VARR);
    std::vector<FeatureActivation> vecCompletedActivations = GetCompletedActivations();
    for (std::vector<FeatureActivation>::iterator it = vecCompletedActivations.begin(); it != vecCompletedActivations.end(); ++it) {
        UniValue actObj(UniValue::VOBJ);
        FeatureActivation completedAct = *it;
        actObj.push_back(Pair("featureid", completedAct.featureId));
        actObj.push_back(Pair("featurename", completedAct.featureName));
        actObj.push_back(Pair("activationblock", completedAct.activationBlock));
        actObj.push_back(Pair("minimumversion", (uint64_t)completedAct.minClientVersion));
        arrayCompletedActivations.push_back(actObj);
    }

    response.push_back(Pair("pendingactivations", arrayPendingActivations));
    response.push_back(Pair("completedactivations", arrayCompletedActivations));

    return response;
}

UniValue elysium_getsto(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw runtime_error(
            "elysium_getsto \"txid\" \"recipientfilter\"\n"
            "\nGet information and recipients of a send-to-owners transaction.\n"
            "\nArguments:\n"
            "1. txid                 (string, required) the hash of the transaction to lookup\n"
            "2. recipientfilter      (string, optional) a filter for recipients (wallet by default, \"*\" for all)\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\" : \"hash\",                (string) the hex-encoded hash of the transaction\n"
            "  \"sendingaddress\" : \"address\",   (string) the Firo address of the sender\n"
            "  \"ismine\" : true|false,          (boolean) whether the transaction involes an address in the wallet\n"
            "  \"confirmations\" : nnnnnnnnnn,   (number) the number of transaction confirmations\n"
            "  \"fee\" : \"n.nnnnnnnn\",           (string) the transaction fee in firos\n"
            "  \"blocktime\" : nnnnnnnnnn,       (number) the timestamp of the block that contains the transaction\n"
            "  \"valid\" : true|false,           (boolean) whether the transaction is valid\n"
            "  \"version\" : n,                  (number) the transaction version\n"
            "  \"type_int\" : n,                 (number) the transaction type as number\n"
            "  \"type\" : \"type\",                (string) the transaction type as string\n"
            "  \"propertyid\" : n,               (number) the identifier of sent tokens\n"
            "  \"divisible\" : true|false,       (boolean) whether the sent tokens are divisible\n"
            "  \"amount\" : \"n.nnnnnnnn\",        (string) the number of tokens sent to owners\n"
            "  \"totalstofee\" : \"n.nnnnnnnn\",   (string) the fee paid by the sender, nominated in ELYSIUM or TELYSIUM\n"
            "  \"recipients\": [                 (array of JSON objects) a list of recipients\n"
            "    {\n"
            "      \"address\" : \"address\",          (string) the Firo address of the recipient\n"
            "      \"amount\" : \"n.nnnnnnnn\"         (string) the number of tokens sent to this recipient\n"
            "    },\n"
            "    ...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_getsto", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" \"*\"")
            + HelpExampleRpc("elysium_getsto", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\", \"*\"")
        );

    uint256 hash = ParseHashV(request.params[0], "txid");
    std::string filterAddress;
    if (request.params.size() > 1) filterAddress = ParseAddressOrWildcard(request.params[1]);

    UniValue txobj(UniValue::VOBJ);
    int populateResult = populateRPCTransactionObject(hash, txobj, "", true, filterAddress);
    if (populateResult != 0) PopulateFailure(populateResult);

    return txobj;
}

UniValue elysium_getcurrentconsensushash(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "elysium_getcurrentconsensushash\n"
            "\nReturns the consensus hash for all balances for the current block.\n"
            "\nResult:\n"
            "{\n"
            "  \"block\" : nnnnnn,          (number) the index of the block this consensus hash applies to\n"
            "  \"blockhash\" : \"hash\",      (string) the hash of the corresponding block\n"
            "  \"consensushash\" : \"hash\"   (string) the consensus hash for the block\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_getcurrentconsensushash", "")
            + HelpExampleRpc("elysium_getcurrentconsensushash", "")
        );

    LOCK(cs_main); // TODO - will this ensure we don't take in a new block in the couple of ms it takes to calculate the consensus hash?

    int block = GetHeight();

    CBlockIndex* pblockindex = chainActive[block];
    uint256 blockHash = pblockindex->GetBlockHash();

    uint256 consensusHash = GetConsensusHash();

    UniValue response(UniValue::VOBJ);
    response.push_back(Pair("block", block));
    response.push_back(Pair("blockhash", blockHash.GetHex()));
    response.push_back(Pair("consensushash", consensusHash.GetHex()));

    return response;
}


UniValue elysium_getbalanceshash(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw runtime_error(
            "elysium_getbalanceshash propertyid\n"
            "\nReturns a hash of the balances for the property.\n"
            "\nArguments:\n"
            "1. propertyid                  (number, required) the property to hash balances for\n"
            "\nResult:\n"
            "{\n"
            "  \"block\" : nnnnnn,          (number) the index of the block this hash applies to\n"
            "  \"blockhash\" : \"hash\",    (string) the hash of the corresponding block\n"
            "  \"propertyid\" : nnnnnn,     (number) the property id of the hashed balances\n"
            "  \"balanceshash\" : \"hash\"  (string) the hash for the balances\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_getbalanceshash", "31")
            + HelpExampleRpc("elysium_getbalanceshash", "31")
        );

    LOCK(cs_main);

    uint32_t propertyId = ParsePropertyId(request.params[0]);
    RequireExistingProperty(propertyId);

    int block = GetHeight();
    CBlockIndex* pblockindex = chainActive[block];
    uint256 blockHash = pblockindex->GetBlockHash();

    uint256 balancesHash = GetBalancesHash(propertyId);

    UniValue response(UniValue::VOBJ);
    response.push_back(Pair("block", block));
    response.push_back(Pair("blockhash", blockHash.GetHex()));
    response.push_back(Pair("propertyid", (uint64_t)propertyId));
    response.push_back(Pair("balanceshash", balancesHash.GetHex()));

    return response;
}

UniValue elysium_recoverlelantusmints(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw runtime_error(
            "elysium_recoverlelantusmints\n"
            "\nRecover Lelantus mints from chain state.\n"
            "\nArguments:\n"
            "1. \"passphrase\"     (string, optional) The wallet passphrase if wallet is encrypted\n"
            "\nResult:\n"
            "\"status\"                       (boolean) return true if success to recover\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_getbalanceshash", "31")
            + HelpExampleRpc("elysium_getbalanceshash", "31")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    bool needToClose = false;
    if (pwalletMain->IsCrypted()) {
        if (request.params.size() < 1) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: require passphrase to unlock wallet");
        }

        SecureString pass;
        pass.reserve(100);

        pass = request.params[0].get_str().c_str();

        if (pass.length() > 0) {
            if (!pwalletMain->Unlock(pass)) {
                throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
            }
            needToClose = true;
        }
    }

    auto result = wallet->SyncWithChain();
    if (needToClose) {
        pwalletMain->nRelockTime = 0;
        pwalletMain->Lock();
    }

    if (!result) {
        return "false";
    }

    return "true";
}

static const CRPCCommand commands[] =
{ //  category                             name                            actor (function)               okSafeMode
  //  ------------------------------------ ------------------------------- ------------------------------ ----------
    { "elysium (data retrieval)", "elysium_getinfo",                   &elysium_getinfo,                    true  },
    { "elysium (data retrieval)", "elysium_getactivations",            &elysium_getactivations,             true  },
    { "elysium (data retrieval)", "elysium_getallbalancesforid",       &elysium_getallbalancesforid,        false },
    { "elysium (data retrieval)", "elysium_getbalance",                &elysium_getbalance,                 false },
    { "elysium (data retrieval)", "elysium_gettransaction",            &elysium_gettransaction,             false },
    { "elysium (data retrieval)", "elysium_getproperty",               &elysium_getproperty,                false },
    { "elysium (data retrieval)", "elysium_listproperties",            &elysium_listproperties,             false },
    { "elysium (data retrieval)", "elysium_getgrants",                 &elysium_getgrants,                  false },
    { "elysium (data retrieval)", "elysium_getsto",                    &elysium_getsto,                     false },
    { "elysium (data retrieval)", "elysium_listblocktransactions",     &elysium_listblocktransactions,      false },
    { "elysium (data retrieval)", "elysium_listpendingtransactions",   &elysium_listpendingtransactions,    false },
    { "elysium (data retrieval)", "elysium_getallbalancesforaddress",  &elysium_getallbalancesforaddress,   false },
    { "elysium (data retrieval)", "elysium_getcurrentconsensushash",   &elysium_getcurrentconsensushash,    false },
    { "elysium (data retrieval)", "elysium_getpayload",                &elysium_getpayload,                 false },
    { "elysium (data retrieval)", "elysium_getbalanceshash",           &elysium_getbalanceshash,            false },
#ifdef ENABLE_WALLET
    { "elysium (data retrieval)", "elysium_listtransactions",          &elysium_listtransactions,           false },
    { "elysium (data retrieval)", "elysium_listlelantusmints",         &elysium_listlelantusmints,          false },
    { "elysium (data retrieval)", "elysium_listpendinglelantusmints",  &elysium_listpendinglelantusmints,   false },
    { "elysium (configuration)",  "elysium_setautocommit",             &elysium_setautocommit,              true  },
    { "elysium (update)",         "elysium_recoverlelantusmints",      &elysium_recoverlelantusmints,       false },
#endif
    { "hidden",                   "elysiumrpc",                        &elysiumrpc,                          true  },

    /* depreciated: */
    { "hidden",                      "getinfo_MP",                     &elysium_getinfo,                    true  },
    { "hidden",                      "getbalance_MP",                  &elysium_getbalance,                 false },
    { "hidden",                      "getallbalancesforaddress_MP",    &elysium_getallbalancesforaddress,   false },
    { "hidden",                      "getallbalancesforid_MP",         &elysium_getallbalancesforid,        false },
    { "hidden",                      "getproperty_MP",                 &elysium_getproperty,                false },
    { "hidden",                      "listproperties_MP",              &elysium_listproperties,             false },
    { "hidden",                      "getgrants_MP",                   &elysium_getgrants,                  false },
    { "hidden",                      "getsto_MP",                      &elysium_getsto,                     false },
    { "hidden",                      "gettransaction_MP",              &elysium_gettransaction,             false },
    { "hidden",                      "listblocktransactions_MP",       &elysium_listblocktransactions,      false },
#ifdef ENABLE_WALLET
    { "hidden",                      "listtransactions_MP",            &elysium_listtransactions,           false },
#endif
};

void RegisterElysiumDataRetrievalRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
