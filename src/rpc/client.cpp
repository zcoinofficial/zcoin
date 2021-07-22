// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/client.h"
#include "rpc/protocol.h"
#include "util.h"

#include <set>
#include <stdint.h>

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <univalue.h>

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
    std::string paramName;  //!< parameter name
};

/**
 * Specifiy a (method, idx, name) here if the argument is a non-string RPC
 * argument and needs to be converted from JSON.
 *
 * @note Parameter indexes start from 0.
 */
static const CRPCConvertParam vRPCConvertParams[] =
{
    { "stop", 0 },
    { "setmocktime", 0, "timestamp" },
    { "getaddednodeinfo", 0 },
    { "generate", 0, "nblocks" },
    { "generate", 1, "maxtries" },
    { "generatetoaddress", 0, "nblocks" },
    { "generatetoaddress", 2, "maxtries" },
    { "getnetworkhashps", 0, "nblocks" },
    { "getnetworkhashps", 1, "height" },
    { "sendtoaddress", 1, "amount" },
    { "sendtoaddress", 4, "subtractfeefromamount" },
    { "settxfee", 0, "amount" },
    { "listaddressbalances", 0, "minamount" },
    { "getreceivedbyaddress", 1, "minconf" },
    { "getreceivedbyaccount", 1, "minconf" },
    { "listreceivedbyaddress", 0, "minconf" },
    { "listreceivedbyaddress", 1, "include_empty" },
    { "listreceivedbyaddress", 2, "include_watchonly" },
    { "listreceivedbyaccount", 0, "minconf" },
    { "listreceivedbyaccount", 1, "include_empty" },
    { "listreceivedbyaccount", 2, "include_watchonly" },
    { "getbalance", 1, "minconf" },
    { "getbalance", 2, "include_watchonly" },
    { "getblockhash", 0, "height" },
    { "move", 2 },
    { "move", 3 },
    { "waitforblockheight", 0, "height" },
    { "waitforblockheight", 1, "timeout" },
    { "waitforblock", 1, "timeout" },
    { "waitfornewblock", 0, "timeout" },
    { "move", 2, "amount" },
    { "move", 3, "minconf" },
    { "sendfrom", 2, "amount" },
    { "sendfrom", 3, "minconf" },
    { "listtransactions", 1, "count" },
    { "listtransactions", 2, "skip" },
    { "listtransactions", 3, "include_watchonly" },
    { "listaccounts", 0, "minconf" },
    { "listaccounts", 1, "include_watchonly" },
    { "walletpassphrase", 1, "timeout" },
    { "getblocktemplate", 0, "template_request" },
    { "listsinceblock", 1, "target_confirmations" },
    { "listsinceblock", 2, "include_watchonly" },
    { "sendmany", 1, "amounts" },
    { "sendmany", 2, "minconf" },
    { "sendmany", 4, "subtractfeefrom" },
    { "addmultisigaddress", 0, "nrequired" },
    { "addmultisigaddress", 1, "keys" },
    { "createmultisig", 0, "nrequired" },
    { "createmultisig", 1, "keys" },
    { "listunspent", 0, "minconf" },
    { "listunspent", 1, "maxconf" },
    { "listunspent", 2, "addresses" },
    { "regeneratemintpool", 0 },
    { "listunspentmintzerocoins", 0 },
    { "listunspentmintzerocoins", 1 },
    { "listunspentmintzerocoins", 2 },
    { "listunspentsigmamints", 0 },
    { "listunspentsigmamints", 1 },
    { "listunspentsigmamints", 2 },
    { "getblock", 1, "verbose" },
    { "getblockheader", 1, "verbose" },
    { "gettransaction", 1, "include_watchonly" },
    { "getrawtransaction", 1, "verbose" },
    { "createrawtransaction", 0, "inputs" },
    { "createrawtransaction", 1, "outputs" },
    { "createrawtransaction", 2, "locktime" },
    { "signrawtransaction", 1, "prevtxs" },
    { "signrawtransaction", 2, "privkeys" },
    { "sendrawtransaction", 1, "allowhighfees" },
    { "fundrawtransaction", 1, "options" },
    { "gettxout", 1, "n" },
    { "gettxout", 2, "include_mempool" },
    { "gettxoutproof", 0, "txids" },
    { "lockunspent", 0, "unlock" },
    { "lockunspent", 1, "transactions" },
    { "importprivkey", 2, "rescan" },
    { "importaddress", 2, "rescan" },
    { "importaddress", 3, "p2sh" },
    { "importpubkey", 2, "rescan" },
    { "importmulti", 0, "requests" },
    { "importmulti", 1, "options" },
    { "verifychain", 0, "checklevel" },
    { "verifychain", 1, "nblocks" },
    { "pruneblockchain", 0, "height" },
    { "keypoolrefill", 0, "newsize" },
    { "getrawmempool", 0, "verbose" },
    { "estimatefee", 0, "nblocks" },
    { "estimatepriority", 0, "nblocks" },
    { "estimatesmartfee", 0, "nblocks" },
    { "estimatesmartpriority", 0, "nblocks" },
    { "prioritisetransaction", 1, "priority_delta" },
    { "prioritisetransaction", 2, "fee_delta" },
    { "setban", 2, "bantime" },
    { "setban", 3, "absolute" },
    { "setnetworkactive", 0, "state" },
    { "getmempoolancestors", 1, "verbose" },
    { "getmempooldescendants", 1, "verbose" },
    { "bumpfee", 1, "options" },
    { "getblockhashes", 0 },
    { "getblockhashes", 1 },
    { "getspentinfo", 0},
    { "getaddresstxids", 0},
    { "getaddressbalance", 0},
    { "getaddressdeltas", 0},
    { "getaddressutxos", 0},
    { "getaddressmempool", 0},
    { "getspecialtxes", 1, "type" },
    { "getspecialtxes", 2, "count" },
    { "getspecialtxes", 3, "skip" },
    { "getspecialtxes", 4, "verbosity" },
    // Echo with conversion (For testing only)
    { "echojson", 0, "arg0" },
    { "echojson", 1, "arg1" },
    { "echojson", 2, "arg2" },
    { "echojson", 3, "arg3" },
    { "echojson", 4, "arg4" },
    { "echojson", 5, "arg5" },
    { "echojson", 6, "arg6" },
    { "echojson", 7, "arg7" },
    { "echojson", 8, "arg8" },
    { "echojson", 9, "arg9" },
        //[firo]
    { "setmininput", 0 },
    { "mint", 0 },
    { "mintzerocoin", 0 },
    { "spendzerocoin", 0 },
    { "spendmanyzerocoin", 0 },
    { "spendmany", 1 },
    { "spendmany", 2 },
    { "spendmany", 4 },
    { "setgenerate", 0 },
    { "setgenerate", 1 },
    { "setmintzerocoinstatus", 2 },
    { "setmintzerocoinstatus", 1 },
    { "setsigmamintstatus", 1 },
    { "setlelantusmintstatus", 1 },
    { "listmintzerocoins", 0 },
    { "listsigmamints", 0 },
    { "listpubcoins", 0 },
    { "listsigmapubcoins", 0 },
    { "listspendzerocoins", 0 },
    { "listspendzerocoins", 1 },
    { "listsigmaspends", 0 },
    { "listsigmaspends", 1 },
    { "listlelantusjoinsplits", 0 },
    { "listlelantusjoinsplits", 1 },
    { "joinsplit", 0 },
    { "joinsplit", 2 },
    { "spendallzerocoin", 0 },
    { "remintzerocointosigma", 0 },
    { "getanonymityset", 0},
    { "getmintmetadata", 0 },
    { "getusedcoinserials", 0 },
    { "getlatestcoinids", 0 },

    /* Elysium - data retrieval calls */
	{ "elysium_gettradehistoryforaddress", 1 },
	{ "elysium_gettradehistoryforaddress", 2 },
	{ "elysium_gettradehistoryforpair", 0 },
	{ "elysium_gettradehistoryforpair", 1 },
	{ "elysium_gettradehistoryforpair", 2 },
	{ "elysium_setautocommit", 0 },
	{ "elysium_getcrowdsale", 0 },
	{ "elysium_getcrowdsale", 1 },
	{ "elysium_getgrants", 0 },
	{ "elysium_getbalance", 1 },
	{ "elysium_getproperty", 0 },
	{ "elysium_listlelantusmints", 0 },
	{ "elysium_listlelantusmints", 1 },
	{ "elysium_listtransactions", 1 },
	{ "elysium_listtransactions", 2 },
	{ "elysium_listtransactions", 3 },
	{ "elysium_listtransactions", 4 },
	{ "elysium_listmints", 0 },
	{ "elysium_listmints", 1 },
	{ "elysium_listmints", 2 },
	{ "elysium_getallbalancesforid", 0 },
	{ "elysium_listblocktransactions", 0 },
	{ "elysium_getorderbook", 0 },
	{ "elysium_getorderbook", 1 },
	{ "elysium_getfeecache", 0 },
	{ "elysium_getfeeshare", 1 },
	{ "elysium_getfeetrigger", 0 },
	{ "elysium_getfeedistribution", 0 },
	{ "elysium_getfeedistributions", 0 },
	{ "elysium_getbalanceshash", 0 },

	/* Elysium - transaction calls */
	{ "elysium_send", 2 },
	{ "elysium_sendsto", 1 },
	{ "elysium_sendsto", 4 },
	{ "elysium_sendall", 2 },
	{ "elysium_sendtrade", 1 },
	{ "elysium_sendtrade", 3 },
	{ "elysium_sendcanceltradesbyprice", 1 },
	{ "elysium_sendcanceltradesbyprice", 3 },
	{ "elysium_sendcanceltradesbypair", 1 },
	{ "elysium_sendcanceltradesbypair", 2 },
	{ "elysium_sendcancelalltrades", 1 },
	{ "elysium_sendissuancefixed", 1 },
	{ "elysium_sendissuancefixed", 2 },
	{ "elysium_sendissuancefixed", 3 },
	{ "elysium_sendissuancefixed", 10 },
	{ "elysium_sendissuancemanaged", 1 },
	{ "elysium_sendissuancemanaged", 2 },
	{ "elysium_sendissuancemanaged", 3 },
	{ "elysium_sendissuancemanaged", 9 },
	{ "elysium_sendissuancecrowdsale", 1 },
	{ "elysium_sendissuancecrowdsale", 2 },
	{ "elysium_sendissuancecrowdsale", 3 },
	{ "elysium_sendissuancecrowdsale", 9 },
	{ "elysium_sendissuancecrowdsale", 11 },
	{ "elysium_sendissuancecrowdsale", 12 },
	{ "elysium_sendissuancecrowdsale", 13 },
	{ "elysium_senddexsell", 1 },
	{ "elysium_senddexsell", 4 },
	{ "elysium_senddexsell", 6 },
	{ "elysium_senddexaccept", 2 },
	{ "elysium_senddexaccept", 4 },
	{ "elysium_sendclosecrowdsale", 1 },
	{ "elysium_sendgrant", 2 },
	{ "elysium_sendrevoke", 1 },
	{ "elysium_sendchangeissuer", 2 },
	{ "elysium_sendenablefreezing", 1 },
	{ "elysium_senddisablefreezing", 1 },
	{ "elysium_sendfreeze", 2 },
	{ "elysium_sendunfreeze", 2 },
	{ "elysium_senddeactivation", 1 },
	{ "elysium_sendactivation", 1 },
	{ "elysium_sendactivation", 2 },
	{ "elysium_sendactivation", 3 },
	{ "elysium_sendalert", 1 },
	{ "elysium_sendalert", 2 },
	{ "elysium_sendcreatedenomination", 1 },
	{ "elysium_sendmint", 1 },
	{ "elysium_sendmint", 2 },
	{ "elysium_sendmint", 3 },
	{ "elysium_sendspend", 1 },
	{ "elysium_sendspend", 2 },
    { "elysium_sendlelantusmint", 1 },
    { "elysium_sendlelantusspend", 1 },

	/* Elysium - raw transaction calls */
	{ "elysium_decodetransaction", 1 },
	{ "elysium_decodetransaction", 2 },
	{ "elysium_createrawtx_reference", 2 },
	{ "elysium_createrawtx_input", 2 },
	{ "elysium_createrawtx_change", 1 },
	{ "elysium_createrawtx_change", 3 },
	{ "elysium_createrawtx_change", 4 },

	/* Elysium - payload creation */
	{ "elysium_createpayload_simplesend", 0 },
	{ "elysium_createpayload_sendall", 0 },
	{ "elysium_createpayload_dexsell", 0 },
	{ "elysium_createpayload_dexsell", 3 },
	{ "elysium_createpayload_dexsell", 5 },
	{ "elysium_createpayload_dexaccept", 0 },
	{ "elysium_createpayload_sto", 0 },
	{ "elysium_createpayload_sto", 2 },
	{ "elysium_createpayload_issuancefixed", 0 },
	{ "elysium_createpayload_issuancefixed", 1 },
	{ "elysium_createpayload_issuancefixed", 2 },
	{ "elysium_createpayload_issuancemanaged", 0 },
	{ "elysium_createpayload_issuancemanaged", 1 },
	{ "elysium_createpayload_issuancemanaged", 2 },
	{ "elysium_createpayload_issuancecrowdsale", 0 },
	{ "elysium_createpayload_issuancecrowdsale", 1 },
	{ "elysium_createpayload_issuancecrowdsale", 2 },
	{ "elysium_createpayload_issuancecrowdsale", 8 },
	{ "elysium_createpayload_issuancecrowdsale", 10 },
	{ "elysium_createpayload_issuancecrowdsale", 11 },
	{ "elysium_createpayload_issuancecrowdsale", 12 },
	{ "elysium_createpayload_closecrowdsale", 0 },
	{ "elysium_createpayload_grant", 0 },
	{ "elysium_createpayload_revoke", 0 },
	{ "elysium_createpayload_changeissuer", 0 },
	{ "elysium_createpayload_trade", 0 },
	{ "elysium_createpayload_trade", 2 },
	{ "elysium_createpayload_canceltradesbyprice", 0 },
	{ "elysium_createpayload_canceltradesbyprice", 2 },
	{ "elysium_createpayload_canceltradesbypair", 0 },
	{ "elysium_createpayload_canceltradesbypair", 1 },
	{ "elysium_createpayload_cancelalltrades", 0 },

	/* Elysium - backwards compatibility */
	{ "getcrowdsale_MP", 0 },
	{ "getcrowdsale_MP", 1 },
	{ "getgrants_MP", 0 },
	{ "send_MP", 2 },
	{ "getbalance_MP", 1 },
	{ "sendtoowners_MP", 1 },
	{ "getproperty_MP", 0 },
	{ "listtransactions_MP", 1 },
	{ "listtransactions_MP", 2 },
	{ "listtransactions_MP", 3 },
	{ "listtransactions_MP", 4 },
	{ "getallbalancesforid_MP", 0 },
	{ "listblocktransactions_MP", 0 },
	{ "getorderbook_MP", 0 },
	{ "getorderbook_MP", 1 },
	{ "trade_MP", 1 }, // depreciated
	{ "trade_MP", 3 }, // depreciated
	{ "trade_MP", 5 }, // depreciated

    /* Evo spork */
    { "spork", 2, "features"},
    /* BIP47 */
    { "listrapaddresses", 0, "verbose"},
};

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int>> members;
    std::set<std::pair<std::string, std::string>> membersByName;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx) {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
    bool convert(const std::string& method, const std::string& name) {
        return (membersByName.count(std::make_pair(method, name)) > 0);
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    const unsigned int n_elem =
        (sizeof(vRPCConvertParams) / sizeof(vRPCConvertParams[0]));

    for (unsigned int i = 0; i < n_elem; i++) {
        members.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                      vRPCConvertParams[i].paramIdx));
        membersByName.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                            vRPCConvertParams[i].paramName));
    }
}

static CRPCConvertTable rpcCvtTable;

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(const std::string& strVal)
{
    UniValue jVal;
    if (!jVal.read(std::string("[")+strVal+std::string("]")) ||
        !jVal.isArray() || jVal.size()!=1)
        throw std::runtime_error(std::string("Error parsing JSON:")+strVal);
    return jVal[0];
}

UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];

        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}

UniValue RPCConvertNamedValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VOBJ);

    for (const std::string &s: strParams) {
        size_t pos = s.find("=");
        if (pos == std::string::npos) {
            throw(std::runtime_error("No '=' in named argument '"+s+"', this needs to be present for every argument (even if it is empty)"));
        }

        std::string name = s.substr(0, pos);
        std::string value = s.substr(pos+1);

        if (!rpcCvtTable.convert(strMethod, name)) {
            // insert string value directly
            params.pushKV(name, value);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.pushKV(name, ParseNonRFCJSONValue(value));
        }
    }

    return params;
}
