// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "crypto/progpow.h"
#include "crypto/progpow/helpers.hpp"
#include "init.h"
#include "validation.h"
#include "miner.h"
#include "net.h"
#include "pow.h"
#include "rpc/server.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validationinterface.h"

#include "masternode-payments.h"
#include "masternode-sync.h"

#include <utility>      // std::pair
#include <memory>
#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include <boost/shared_ptr.hpp>

#include <univalue.h>

extern CTxPoolAggregate txpools;

/**
 * ProgPow
 */
std::map<std::string, CBlock> mapPPBlockTemplates;

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is nonpositive.
 * If 'height' is nonnegative, compute the estimate at the time when a given block was found.
 */
UniValue GetNetworkHashPS(int lookup, int height) {
    CBlockIndex *pb = chainActive.Tip();

    if (height >= 0 && height < chainActive.Height())
        pb = chainActive[height];

    if (pb == NULL || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0)
        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    CBlockIndex *pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

UniValue getnetworkhashps(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "getnetworkhashps ( nblocks height )\n"
            "\nReturns the estimated network hashes per second based on the last n blocks.\n"
            "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
            "Pass in [height] to estimate the network speed at the time when a certain block was found.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric, optional, default=120) The number of blocks, or -1 for blocks since last difficulty change.\n"
            "2. height      (numeric, optional, default=-1) To estimate at the time of the given height.\n"
            "\nResult:\n"
            "x             (numeric) Hashes per second estimated\n"
            "\nExamples:\n"
            + HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
       );

    LOCK(cs_main);
    return GetNetworkHashPS(request.params.size() > 0 ? request.params[0].get_int() : 120, request.params.size() > 1 ? request.params[1].get_int() : -1);
}

UniValue generateBlocks(boost::shared_ptr<CReserveScript> coinbaseScript, int nGenerate, uint64_t nMaxTries, bool keepScript)
{
    static const int nInnerLoopCount = 0x10000;
    int nHeightEnd = 0;
    int nHeight = 0;

    {   // Don't keep cs_main locked
        LOCK(cs_main);
        nHeight    = chainActive.Height();
        nHeightEnd = nHeight + nGenerate;
    }

    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR);
    
    while (nHeight < nHeightEnd)
    {
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(coinbaseScript->reserveScript));
        
        if (!pblocktemplate.get()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        }

        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            IncrementExtraNonce(pblock, chainActive.Tip(), nExtraNonce);
        }

        /**
         * @AndreaLanfranchi. This loop imho makes no sense for PP
         * as its' purpose is to "mine" blocks but reading the code the attempts
         * are interrupted on nMaxTries (default 1M) or when the nonce overflows nInnerLoopCount (65535)
         * whichever the first. Understandably on PP the nInnerLoopCount si hit quickly as the
         * nonce range is quite wide (64bits)
         */

        if (pblock->IsProgPow()) {
            while (nMaxTries > 0 && pblock->nNonce64 < nInnerLoopCount) {
                uint256 mix_hash;
                auto final_hash{progpow_hash_full(*pblock, mix_hash)};
                if (CheckProofOfWork(final_hash, pblock->nBits, Params().GetConsensus()))
                {
                    pblock->mix_hash = mix_hash;
                    break;
                }
                ++pblock->nNonce64;
                --nMaxTries;
            }
        } else if (pblock->IsMTP()) {
            while (nMaxTries > 0 && pblock->nNonce < nInnerLoopCount) {
                // Note from @AndreaLanfranchi for future devs
                // Not sure about this but my strong guess is 
                // pblock->mtpHashValue should be valued only on positive validation
                // of proof. As it's code I'm not involved into I'm leaving for reference
                pblock->mtpHashValue = mtp::hash(*pblock, Params().GetConsensus().powLimit);
                if (CheckProofOfWork(pblock->mtpHashValue, pblock->nBits, Params().GetConsensus()))
                    break;
                ++pblock->nNonce;
                --nMaxTries;
            }
        } else {
            while (nMaxTries > 0 && pblock->nNonce < nInnerLoopCount && !CheckProofOfWork(pblock->GetPoWHash(nHeight+1), pblock->nBits, Params().GetConsensus())) {
                ++pblock->nNonce;
                --nMaxTries;
                pblock->cachedPoWHash.SetNull();
            }
        }
        if (nMaxTries == 0) {
            break;
        }
        if (pblock->nNonce == nInnerLoopCount || pblock->nNonce64 == nInnerLoopCount) {
            continue;
        }
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
        if (!ProcessNewBlock(Params(), shared_pblock, true, NULL))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
        ++nHeight;
        blockHashes.push_back(pblock->GetHash().GetHex());

        //mark script as important because it was used at least for one coinbase output if the script came from the wallet
        if (keepScript)
        {
            coinbaseScript->KeepScript();
        }
    }
    return blockHashes;
}

UniValue generate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "generate nblocks ( maxtries )\n"
            "\nMine up to nblocks blocks immediately (before the RPC call returns)\n"
            "\nArguments:\n"
            "1. nblocks      (numeric, required) How many blocks are generated immediately.\n"
            "2. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
            "\nResult:\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks\n"
            + HelpExampleCli("generate", "11")
        );

    int nGenerate = request.params[0].get_int();
    uint64_t nMaxTries = 1000000;
    if (request.params.size() > 1) {
        nMaxTries = request.params[1].get_int();
    }

    boost::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript)
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    //throw an error if no script was provided
    if (coinbaseScript->reserveScript.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");

    return generateBlocks(coinbaseScript, nGenerate, nMaxTries, true);
}

UniValue generatetoaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "generatetoaddress nblocks address (maxtries)\n"
            "\nMine blocks immediately to a specified address (before the RPC call returns)\n"
            "\nArguments:\n"
            "1. nblocks      (numeric, required) How many blocks are generated immediately.\n"
            "2. address      (string, required) The address to send the newly generated bitcoin to.\n"
            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
            "\nResult:\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
        );

    int nGenerate = request.params[0].get_int();
    uint64_t nMaxTries = 1000000;
    if (request.params.size() > 2) {
        nMaxTries = request.params[2].get_int();
    }

    CBitcoinAddress address(request.params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");

    boost::shared_ptr<CReserveScript> coinbaseScript(new CReserveScript());
    coinbaseScript->reserveScript = GetScriptForDestination(address.Get());

    return generateBlocks(coinbaseScript, nGenerate, nMaxTries, false);
}


UniValue setgenerate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
                "setgenerate generate ( genproclimit )\n"
                        "\nSet 'generate' true or false to turn generation on or off.\n"
                        "Generation is limited to 'genproclimit' processors, 1 is unlimited.\n"
                        "\nArguments:\n"
                        "1. generate         (boolean, required) Set to true to turn on generation, off to turn off.\n"
                        "2. genproclimit     (numeric, optional) Set the processor limit for when generation is on. Can be 1 for unlimited.\n"
                        "\nExamples:\n"
                        "\nSet the generation on with a limit of one processor\n"
                + HelpExampleCli("setgenerate", "true 1") +
                "\nTurn off generation\n"
                + HelpExampleCli("setgenerate", "false") +
                "\nUsing json rpc\n"
                + HelpExampleRpc("setgenerate", "true, 1")
        );

    if (Params().MineBlocksOnDemand())
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Use the generate method instead of setgenerate on this network");

    bool fGenerate = request.params[0].get_bool();
    int nGenProcLimit = GetArg("-genproclimit", DEFAULT_GENERATE_THREADS);
    if (request.params.size() > 1)
    {
        nGenProcLimit = request.params[1].get_int();
        if (nGenProcLimit == 0)
            fGenerate = false;
    }

    GenerateBitcoins(fGenerate, nGenProcLimit, Params());

    return NullUniValue;
}


UniValue getmininginfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getmininginfo\n"
            "\nReturns a json object containing mining-related information."
            "\nResult:\n"
            "{\n"
            "  \"blocks\": nnn,             (numeric) The current block\n"
            "  \"currentblocksize\": nnn,   (numeric) The last block size\n"
            "  \"currentblockweight\": nnn, (numeric) The last block weight\n"
            "  \"currentblocktx\": nnn,     (numeric) The last block transaction\n"
            "  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n"
            "  \"errors\": \"...\"            (string) Current errors\n"
            "  \"genproclimit\": n          (numeric) The processor limit for generation. -1 if no generation\n"
            "  \"networkhashps\": nnn,      (numeric) The network hashes per second\n"
            "  \"pooledtx\": n              (numeric) The size of the mempool\n"
            "  \"testnet\": true|false      (boolean) If using testnet or not\n"
            "  \"chain\": \"xxxx\",           (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
        );


    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("blocks",           (int)chainActive.Height()));
    obj.push_back(Pair("currentblocksize", (uint64_t)nLastBlockSize));
    obj.push_back(Pair("currentblockweight", (uint64_t)nLastBlockWeight));
    obj.push_back(Pair("currentblocktx",   (uint64_t)nLastBlockTx));
    obj.push_back(Pair("difficulty",       (double)GetDifficulty()));
    obj.push_back(Pair("errors",           GetWarnings("statusbar")));
    obj.push_back(Pair("genproclimit",     (int)GetArg("-genproclimit", DEFAULT_GENERATE_THREADS)));
    obj.push_back(Pair("networkhashps",    getnetworkhashps(request)));
    obj.push_back(Pair("pooledtx",         (uint64_t)mempool.size()));
    obj.push_back(Pair("chain",            Params().NetworkIDString()));
    return obj;
}


// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
UniValue prioritisetransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "prioritisetransaction <txid> <priority delta> <fee delta>\n"
            "Accepts the transaction into mined blocks at a higher (or lower) priority\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id.\n"
            "2. priority_delta (numeric, required) The priority to add or subtract.\n"
            "                  The transaction selection algorithm considers the tx as it would have a higher priority.\n"
            "                  (priority of a transaction is calculated: coinage * value_in_satoshis / txsize) \n"
            "3. fee_delta      (numeric, required) The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee.\n"
            "\nResult:\n"
            "true              (boolean) Returns true\n"
            "\nExamples:\n"
            + HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
        );

    LOCK(cs_main);

    uint256 hash = ParseHashStr(request.params[0].get_str(), "txid");
    CAmount nAmount = request.params[2].get_int64();

    txpools.PrioritiseTransaction(hash, request.params[0].get_str(), request.params[1].get_real(), nAmount);

    return true;
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    std::string strRejectReason = state.GetRejectReason();
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid())
    {
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

std::string gbt_vb_name(const Consensus::DeploymentPos pos) {
    const struct BIP9DeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
    std::string s = vbinfo.name;
    if (!vbinfo.gbt_force) {
        s.insert(s.begin(), '!');
    }
    return s;
}

UniValue getblocktemplate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getblocktemplate ( TemplateRequest )\n"
            "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
            "It returns data needed to construct a block to work on.\n"
            "For full specification, see BIPs 22, 23, 9, and 145:\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki#getblocktemplate_changes\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0145.mediawiki\n"

            "\nArguments:\n"
            "1. template_request         (json object, optional) A json object in the following spec\n"
            "     {\n"
            "       \"mode\":\"template\"    (string, optional) This must be set to \"template\", \"proposal\" (see BIP 23), or omitted\n"
            "       \"capabilities\":[     (array, optional) A list of strings\n"
            "           \"support\"          (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'\n"
            "           ,...\n"
            "       ],\n"
            "       \"rules\":[            (array, optional) A list of strings\n"
            "           \"support\"          (string) client side supported softfork deployment\n"
            "           ,...\n"
            "       ]\n"
            "     }\n"
            "\n"

            "\nResult:\n"
            "{\n"
            "  \"version\" : n,                    (numeric) The preferred block version\n"
            "  \"rules\" : [ \"rulename\", ... ],    (array of strings) specific block rules that are to be enforced\n"
            "  \"vbavailable\" : {                 (json object) set of pending, supported versionbit (BIP 9) softfork deployments\n"
            "      \"rulename\" : bitnumber          (numeric) identifies the bit number as indicating acceptance and readiness for the named softfork rule\n"
            "      ,...\n"
            "  },\n"
            "  \"vbrequired\" : n,                 (numeric) bit mask of versionbits the server requires set in submissions\n"
            "  \"previousblockhash\" : \"xxxx\",     (string) The hash of current highest block\n"
            "  \"transactions\" : [                (array) contents of non-coinbase transactions that should be included in the next block\n"
            "      {\n"
            "         \"data\" : \"xxxx\",             (string) transaction data encoded in hexadecimal (byte-for-byte)\n"
            "         \"txid\" : \"xxxx\",             (string) transaction id encoded in little-endian hexadecimal\n"
            "         \"hash\" : \"xxxx\",             (string) hash encoded in little-endian hexadecimal (including witness data)\n"
            "         \"depends\" : [                (array) array of numbers \n"
            "             n                          (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is\n"
            "             ,...\n"
            "         ],\n"
            "         \"fee\": n,                    (numeric) difference in value between transaction inputs and outputs (in Satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one\n"
            "         \"sigops\" : n,                (numeric) total SigOps cost, as counted for purposes of block limits; if key is not present, sigop cost is unknown and clients MUST NOT assume it is zero\n"
            "         \"weight\" : n,                (numeric) total transaction weight, as counted for purposes of block limits\n"
            "         \"required\" : true|false      (boolean) if provided and true, this transaction must be in the final block\n"
            "      }\n"
            "      ,...\n"
            "  ],\n"
            "  \"coinbaseaux\" : {                 (json object) data that should be included in the coinbase's scriptSig content\n"
            "      \"flags\" : \"xx\"                  (string) key name is to be ignored, and value included in scriptSig\n"
            "  },\n"
            "  \"coinbasevalue\" : n,              (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees (in Satoshis)\n"
            "  \"coinbasetxn\" : { ... },          (json object) information for coinbase transaction\n"
            "  \"target\" : \"xxxx\",                (string) The hash target\n"
            "  \"mintime\" : xxx,                  (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mutable\" : [                     (array of string) list of ways the block template may be changed \n"
            "     \"value\"                          (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'\n"
            "     ,...\n"
            "  ],\n"
            "  \"noncerange\" : \"00000000ffffffff\",(string) A range of valid nonces\n"
            "  \"sigoplimit\" : n,                 (numeric) limit of sigops in blocks\n"
            "  \"sizelimit\" : n,                  (numeric) limit of block size\n"
            "  \"weightlimit\" : n,                (numeric) limit of block weight\n"
            "  \"curtime\" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"xxxxxxxx\",              (string) compressed target of next block\n"
            "  \"height\" : n                      (numeric) The height of the next block\n"
            "  \"znode\" : [                       (array) required znode payments that must be included in the next block\n"
            "      {\n"
            "         \"payee\" : \"xxxx\",          (string) payee address\n"
            "         \"script\" : \"xxxx\",         (string) payee scriptPubKey\n"
            "         \"amount\": n                (numeric) required amount to pay\n"
            "      }\n"
            "  },\n"
            "  \"znode_payments_started\" :  true|false, (boolean) true, if znode payments started\n"
            "  \"znode_payments_enforced\" : true|false, (boolean) true, if znode payments are enforced\n"
            "  \"coinbase_payload\" : \"xxxxxxxx\"    (string) coinbase transaction payload data encoded in hexadecimal\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getblocktemplate", "")
            + HelpExampleRpc("getblocktemplate", "")
         );

    LOCK(cs_main);

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    std::set<std::string> setClientRules;
    int64_t nMaxVersionPreVB = -1;
    if (request.params.size() > 0)
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = find_value(oparam, "mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = find_value(oparam, "data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            BlockMap::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end()) {
                CBlockIndex *pindex = mi->second;
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = chainActive.Tip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            CValidationState state;
            TestBlockValidity(state, Params(), block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }

        const UniValue& aClientRules = find_value(oparam, "rules");
        if (aClientRules.isArray()) {
            for (unsigned int i = 0; i < aClientRules.size(); ++i) {
                const UniValue& v = aClientRules[i];
                setClientRules.insert(v.get_str());
            }
        } else {
            // NOTE: It is important that this NOT be read if versionbits is supported
            const UniValue& uvMaxVersion = find_value(oparam, "maxversion");
            if (uvMaxVersion.isNum()) {
                nMaxVersionPreVB = uvMaxVersion.get_int64();
            }
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Firo is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Firo is downloading blocks...");

    if (Params().GetConsensus().IsMain() && !masternodeSync.IsSynced())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Firo Core is syncing with network...");

    static unsigned int nTransactionsUpdatedLast;
    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        boost::system_time checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain.SetHex(lpstr.substr(0, 64));
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = chainActive.Tip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release the wallet and main lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            checktxtime = boost::get_system_time() + boost::posix_time::minutes(1);

            boost::unique_lock<boost::mutex> lock(csBestBlock);
            while (chainActive.Tip()->GetBlockHash() == hashWatchedChain && IsRPCRunning())
            {
                if (!cvBlockChange.timed_wait(lock, checktxtime))
                {
                    // Timeout: Check transactions for update
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += boost::posix_time::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    const struct BIP9DeploymentInfo& segwit_info = VersionBitsDeploymentInfo[Consensus::DEPLOYMENT_SEGWIT];
    // If the caller is indicating segwit support, then allow CreateNewBlock()
    // to select witness transactions, after segwit activates (otherwise
    // don't).
    bool fSupportsSegwit = setClientRules.find(segwit_info.name) != setClientRules.end();

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static std::unique_ptr<CBlockTemplate> pblocktemplate;
    // Cache whether the last invocation was with segwit support, to avoid returning
    // a segwit-block to a non-segwit caller.
    static bool fLastTemplateSupportsSegwit = true;
    if (pindexPrev != chainActive.Tip() ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5) ||
        fLastTemplateSupportsSegwit != fSupportsSegwit)
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = nullptr;
        mapPPBlockTemplates.clear();

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = chainActive.Tip();
        nStart = GetTime();
        fLastTemplateSupportsSegwit = fSupportsSegwit;

        // Create new block
        CScript scriptDummy = CScript() << OP_TRUE;
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(scriptDummy, fSupportsSegwit);
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience
    const Consensus::Params& consensusParams = Params().GetConsensus();

    // Update nTime
    UpdateTime(pblock, consensusParams, pindexPrev);
    pblock->nNonce = 0;

    // TODO: support segwit
    // NOTE: If at some point we support pre-segwit miners post-segwit-activation, this needs to take segwit support into consideration
//    const bool fPreSegWit = (THRESHOLD_ACTIVE != VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_SEGWIT, versionbitscache));
    const bool fPreSegWit = false;

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    std::map<uint256, int64_t> setTxIndex;
    int i = 0;
    for (const auto& it : pblock->vtx) {
        const CTransaction& tx = *it;
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.push_back(Pair("data", EncodeHexTx(tx)));
        entry.push_back(Pair("txid", txHash.GetHex()));
        entry.push_back(Pair("hash", tx.GetWitnessHash().GetHex()));

        UniValue deps(UniValue::VARR);
        BOOST_FOREACH (const CTxIn &in, tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.push_back(Pair("depends", deps));

        int index_in_template = i - 1;
        entry.push_back(Pair("fee", pblocktemplate->vTxFees[index_in_template]));
        int64_t nTxSigOps = pblocktemplate->vTxSigOpsCost[index_in_template];
        if (fPreSegWit) {
            assert(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
            nTxSigOps /= WITNESS_SCALE_FACTOR;
        }
        entry.push_back(Pair("sigops", nTxSigOps));
        entry.push_back(Pair("weight", GetTransactionWeight(tx)));

        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("capabilities", aCaps));

    UniValue aRules(UniValue::VARR);
    UniValue vbavailable(UniValue::VOBJ);
    for (int j = 0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
        // MTP deployment has different set of rules
        if (j == Consensus::DEPLOYMENT_MTP)
            continue;

        Consensus::DeploymentPos pos = Consensus::DeploymentPos(j);
        ThresholdState state = VersionBitsState(pindexPrev, consensusParams, pos, versionbitscache);
        switch (state) {
            case THRESHOLD_DEFINED:
            case THRESHOLD_FAILED:
                // Not exposed to GBT at all
                break;
            case THRESHOLD_LOCKED_IN:
                // Ensure bit is set in block version
                pblock->nVersion |= VersionBitsMask(consensusParams, pos);
                // FALL THROUGH to get vbavailable set...
            case THRESHOLD_STARTED:
            {
                const struct BIP9DeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                vbavailable.push_back(Pair(gbt_vb_name(pos), consensusParams.vDeployments[pos].bit));
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    if (!vbinfo.gbt_force) {
                        // If the client doesn't support this, don't indicate it in the [default] version
                        pblock->nVersion &= ~VersionBitsMask(consensusParams, pos);
                    }
                }
                break;
            }
            case THRESHOLD_ACTIVE:
            {
                // Add to rules only
                const struct BIP9DeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                aRules.push_back(gbt_vb_name(pos));
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    // Not supported by the client; make sure it's safe to proceed
                    if (!vbinfo.gbt_force) {
                        // If we do anything other than throw an exception here, be sure version/force isn't sent to old clients
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Support for '%s' rule requires explicit client support", vbinfo.name));
                    }
                }
                break;
            }
        }
    }
    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("rules", aRules));
    result.push_back(Pair("vbavailable", vbavailable));
    result.push_back(Pair("vbrequired", int(0)));

    if (nMaxVersionPreVB >= 2) {
        // If VB is supported by the client, nMaxVersionPreVB is -1, so we won't get here
        // Because BIP 34 changed how the generation transaction is serialized, we can only use version/force back to v2 blocks
        // This is safe to do [otherwise-]unconditionally only because we are throwing an exception above if a non-force deployment gets activated
        // Note that this can probably also be removed entirely after the first BIP9 non-force deployment (ie, probably segwit) gets activated
        aMutable.push_back("version/force");
    }

    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("transactions", transactions));
    result.push_back(Pair("coinbaseaux", aux));
    result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0]->vout[0].nValue));
    result.push_back(Pair("longpollid", chainActive.Tip()->GetBlockHash().GetHex() + i64tostr(nTransactionsUpdatedLast)));
    result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));
    int64_t nSigOpLimit = MAX_BLOCK_SIGOPS_COST;
    if (fPreSegWit) {
        assert(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
        nSigOpLimit /= WITNESS_SCALE_FACTOR;
    }
    result.push_back(Pair("sigoplimit", nSigOpLimit));
    if (fPreSegWit) {
        result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_BASE_SIZE));
    } else {
        result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_SERIALIZED_SIZE));
        result.push_back(Pair("weightlimit", (int64_t)MAX_BLOCK_WEIGHT));
    }
    result.push_back(Pair("curtime", pblock->GetBlockTime()));
    result.push_back(Pair("bits", strprintf("%08x", pblock->nBits)));
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));

    // Get expected MN/superblock payees. The call to GetBlockTxOuts might fail on regtest/devnet or when
    // testnet is reset. This is fine and we ignore failure (blocks will be accepted)
    std::vector<CTxOut> voutMasternodePayments;
    mnpayments.GetBlockTxOuts(chainActive.Height() + 1, 0, voutMasternodePayments);

    UniValue masternodeObj(UniValue::VARR);
    for (const auto& txout : pblocktemplate->voutMasternodePayments) {
        CTxDestination address1;
        ExtractDestination(txout.scriptPubKey, address1);
        CBitcoinAddress address2(address1);

        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("payee", address2.ToString().c_str()));
        obj.push_back(Pair("script", HexStr(txout.scriptPubKey)));
        obj.push_back(Pair("amount", txout.nValue));
        masternodeObj.push_back(obj);
    }

    result.push_back(Pair("znode", masternodeObj));
    result.push_back(Pair("znode_payments_started", true));
    result.push_back(Pair("znode_payments_enforced", true));

    if (pindexPrev->nHeight+1 >= Params().GetConsensus().DIP0003Height) {
        result.push_back(Pair("coinbase_payload", HexStr(pblock->vtx[0]->vExtraPayload)));
    }

    if (!pblocktemplate->vchCoinbaseCommitment.empty() && fSupportsSegwit) {
        result.push_back(Pair("default_witness_commitment", HexStr(pblocktemplate->vchCoinbaseCommitment.begin(), pblocktemplate->vchCoinbaseCommitment.end())));
    }

    if (pblock->IsProgPow()) {
        static std::string lastHeader{};
        if (mapPPBlockTemplates.count(lastHeader) && ((pblock->nTime - 30) < mapPPBlockTemplates.at(lastHeader).nTime))
        {
            result.pushKV("pprpcheader", lastHeader);
            result.pushKV("pprpcepoch", ethash::get_epoch_number(pblock->nHeight));
            return result;
        }
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
        lastHeader = pblock->GetProgPowHeaderHash().GetHex();
        result.pushKV("pprpcheader", lastHeader);
        result.pushKV("pprpcheader", ethash::get_epoch_number(pblock->nHeight));
        mapPPBlockTemplates[lastHeader] = *pblock;
    }

    return result;
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {}

protected:
    virtual void BlockChecked(const CBlock& block, const CValidationState& stateIn) {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

UniValue pprpcsb(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3) {
        throw std::runtime_error(
                "pprpcsb \"header_hash\" \"mix_hash\" \"nonce\"\n"
                "\nAttempts to submit a progpow solution to block via rpc.\n"

                "\nArguments\n"
                "1. \"header_hash\"        (string, required) the prow_pow header hash that was given to the gpu miner from this rpc client\n"
                "2. \"mix_hash\"           (string, required) the mix hash that was mined by the gpu miner via rpc\n"
                "3. \"nonce\"              (string, required) the nonce of the block that hashed the valid block\n"
                "\nResult:\n"
                "\nExamples:\n"
                + HelpExampleCli("pprpcsb", "\"header_hash\" \"mix_hash\" 100000")
                + HelpExampleRpc("pprpcsb", "\"header_hash\" \"mix_hash\" 100000")
        );
    }

    std::string header_hash = request.params[0].get_str();
    std::string mix_hash = request.params[1].get_str();
    std::string nonce_str = request.params[2].get_str();

    // Parse nonce
    uint64_t nonce{0};
    try
    {
        std::stoull(nonce_str, nullptr, 0);
    }
    catch(...)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid hex nonce");
    }
    
    // Check provided header_hash is in cache
    if (!mapPPBlockTemplates.count(header_hash))
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Job not found");
    }
    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    *blockptr = mapPPBlockTemplates.at(header_hash);

    // Check provided solution is formally valid
    uint256 act_mix_hash = uint256S(mix_hash);
    uint256 exp_mix_hash;
    blockptr->nNonce64 = nonce;
    uint256 final_hash = blockptr->GetProgPowHashFull(exp_mix_hash);
    if (act_mix_hash != exp_mix_hash)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Bad solution : mismatching mix_hash");
    }
   
    // Check provided solution honors boundaries
    if (!CheckProofOfWork(final_hash, blockptr->nBits, Params().GetConsensus()))
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Bad solution : not below target");
    }
    
    // Store mix_hash
    blockptr->mix_hash = exp_mix_hash;
    uint256 blockHash = blockptr->GetHash();

    bool fBlockPresent{false};
    {
        LOCK(cs_main);
        BlockMap::iterator mi{mapBlockIndex.find(blockHash)};
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* indexptr{mi->second};
            if (indexptr->IsValid(BLOCK_VALID_SCRIPTS))
            {
                return "duplicate";
            }
            if (indexptr->nStatus & BLOCK_FAILED_MASK)
            {
                return "duplicate-invalid";
            }
            
        }
        // Otherwise, we might only have the header - process the block before returning
        fBlockPresent = true;

        mi = mapBlockIndex.find(blockptr->hashPrevBlock);
        if (mi != mapBlockIndex.end()) {
            UpdateUncommittedBlockStructures(*blockptr, mi->second, Params().GetConsensus());
        }
    }

    // Process block
    submitblock_StateCatcher sc(blockHash);
    RegisterValidationInterface(&sc);
    bool fAccepted = ProcessNewBlock(Params(), blockptr, true, nullptr);
    UnregisterValidationInterface(&sc);
    if (fBlockPresent)
    {
        if (fAccepted && !sc.found)
        {
            return "duplicate-inconclusive";
        }
        return "duplicate";
    }
    if (!sc.found)
    {
        return "inconclusive";
    }
    
    return BIP22ValidationResult(sc.state);
}

UniValue submitblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "submitblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nAttempts to submit new block to network.\n"
            "The 'jsonparametersobject' parameter is currently ignored.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments\n"
            "1. \"hexdata\"        (string, required) the hex-encoded block data to submit\n"
            "2. \"parameters\"     (string, optional) object of optional parameters\n"
            "    {\n"
            "      \"workid\" : \"id\"    (string, optional) if the server provided a workid, it MUST be included with submissions\n"
            "    }\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
        );

    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block does not start with a coinbase");
    }

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex *pindex = mi->second;
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                return "duplicate";
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return "duplicate-invalid";
            // Otherwise, we might only have the header - process the block before returning
            fBlockPresent = true;
        }
    }

    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi != mapBlockIndex.end()) {
            UpdateUncommittedBlockStructures(block, mi->second, Params().GetConsensus());
        }
    }

    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    bool fAccepted = ProcessNewBlock(Params(), blockptr, true, NULL);
    UnregisterValidationInterface(&sc);
    if (fBlockPresent)
    {
        if (fAccepted && !sc.found)
            return "duplicate-inconclusive";
        return "duplicate";
    }
    if (!sc.found)
        return "inconclusive";
    return BIP22ValidationResult(sc.state);
}


UniValue estimatefee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "estimatefee nblocks\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks. Uses virtual transaction size of transaction\n"
            "as defined in BIP 141 (witness data is discounted).\n"
            "\nArguments:\n"
            "1. nblocks     (numeric, required)\n"
            "\nResult:\n"
            "n              (numeric) estimated fee-per-kilobyte\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate.\n"
            "-1 is always returned for nblocks == 1 as it is impossible to calculate\n"
            "a fee that is high enough to get reliably included in the next block.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatefee", "6")
            );

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VNUM));

    int nBlocks = request.params[0].get_int();
    if (nBlocks < 1)
        nBlocks = 1;

    CFeeRate feeRate = mempool.estimateFee(nBlocks);
    if (feeRate == CFeeRate(0))
        return -1.0;

    return ValueFromAmount(feeRate.GetFeePerK());
}

UniValue estimatepriority(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "estimatepriority nblocks\n"
            "\nDEPRECATED. Estimates the approximate priority a zero-fee transaction needs to begin\n"
            "confirmation within nblocks blocks.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric, required)\n"
            "\nResult:\n"
            "n              (numeric) estimated priority\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatepriority", "6")
            );

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VNUM));

    int nBlocks = request.params[0].get_int();
    if (nBlocks < 1)
        nBlocks = 1;

    return mempool.estimatePriority(nBlocks);
}

UniValue estimatesmartfee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "estimatesmartfee nblocks\n"
            "\nWARNING: This interface is unstable and may disappear or change!\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks if possible and return the number of blocks\n"
            "for which the estimate is valid. Uses virtual transaction size as defined\n"
            "in BIP 141 (witness data is discounted).\n"
            "\nArguments:\n"
            "1. nblocks     (numeric)\n"
            "\nResult:\n"
            "{\n"
            "  \"feerate\" : x.x,     (numeric) estimate fee-per-kilobyte (in BTC)\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "However it will not return a value below the mempool reject fee.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatesmartfee", "6")
            );

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VNUM));

    int nBlocks = request.params[0].get_int();

    UniValue result(UniValue::VOBJ);
    int answerFound;
    CFeeRate feeRate = mempool.estimateSmartFee(nBlocks, &answerFound);
    result.push_back(Pair("feerate", feeRate == CFeeRate(0) ? -1.0 : ValueFromAmount(feeRate.GetFeePerK())));
    result.push_back(Pair("blocks", answerFound));
    return result;
}

UniValue estimatesmartpriority(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "estimatesmartpriority nblocks\n"
            "\nDEPRECATED. WARNING: This interface is unstable and may disappear or change!\n"
            "\nEstimates the approximate priority a zero-fee transaction needs to begin\n"
            "confirmation within nblocks blocks if possible and return the number of blocks\n"
            "for which the estimate is valid.\n"
            "\nArguments:\n"
            "1. nblocks     (numeric, required)\n"
            "\nResult:\n"
            "{\n"
            "  \"priority\" : x.x,    (numeric) estimated priority\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "However if the mempool reject fee is set it will return 1e9 * MAX_MONEY.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatesmartpriority", "6")
            );

    RPCTypeCheck(request.params, boost::assign::list_of(UniValue::VNUM));

    int nBlocks = request.params[0].get_int();

    UniValue result(UniValue::VOBJ);
    int answerFound;
    double priority = mempool.estimateSmartPriority(nBlocks, &answerFound);
    result.push_back(Pair("priority", priority));
    result.push_back(Pair("blocks", answerFound));
    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "getnetworkhashps",       &getnetworkhashps,       true,  {"nblocks","height"} },
    { "mining",             "getmininginfo",          &getmininginfo,          true,  {} },
    { "mining",             "prioritisetransaction",  &prioritisetransaction,  true,  {"txid","priority_delta","fee_delta"} },
    { "mining",             "getblocktemplate",       &getblocktemplate,       true,  {"template_request"} },
    { "mining",             "pprpcsb",                &pprpcsb,                true,  {"header_hash","mix_hash", "nonce"} },
    { "mining",             "submitblock",            &submitblock,            true,  {"hexdata","parameters"} },

    { "generating",         "setgenerate",            &setgenerate,            true  },
    { "generating",         "generate",               &generate,               true,  {"nblocks","maxtries"} },
    { "generating",         "generatetoaddress",      &generatetoaddress,      true,  {"nblocks","address","maxtries"} },

    { "util",               "estimatefee",            &estimatefee,            true,  {"nblocks"} },
    { "util",               "estimatepriority",       &estimatepriority,       true,  {"nblocks"} },
    { "util",               "estimatesmartfee",       &estimatesmartfee,       true,  {"nblocks"} },
    { "util",               "estimatesmartpriority",  &estimatesmartpriority,  true,  {"nblocks"} },
};

void RegisterMiningRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
