/**
 * @file rpctxobject.cpp
 *
 * Handler for populating RPC transaction objects.
 */

#include "elysium/rpctxobject.h"


#include "elysium/errors.h"

#include "elysium/elysium.h"
#include "elysium/pending.h"
#include "elysium/rpctxobject.h"
#include "elysium/sp.h"
#include "elysium/sto.h"
#include "elysium/tx.h"
#include "elysium/utilsbitcoin.h"
#include "elysium/wallettxs.h"

#include "chainparams.h"
#include "validation.h"
#include "primitives/transaction.h"
#include "sync.h"
#include "uint256.h"

#include <univalue.h>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <stdint.h>
#include <string>
#include <vector>

// Namespaces
using namespace elysium;

/**
 * Function to standardize RPC output for transactions into a JSON object in either basic or extended mode.
 *
 * Use basic mode for generic calls (e.g. elysium_gettransaction/elysium_listtransaction etc.)
 * Use extended mode for transaction specific calls (e.g. elysium_getsto, elysium_gettrade etc.)
 *
 * DEx payments and the extended mode are only available for confirmed transactions.
 */
int populateRPCTransactionObject(const uint256& txid, UniValue& txobj, std::string filterAddress, bool extendedDetails, std::string extendedDetailsFilter)
{
    // retrieve the transaction from the blockchain and obtain it's height/confs/time
    CTransactionRef tx;
    uint256 blockHash;
    if (!GetTransaction(txid, tx, Params().GetConsensus(), blockHash, true)) {
        return MP_TX_NOT_FOUND;
    }

    return populateRPCTransactionObject(*tx, blockHash, txobj, filterAddress, extendedDetails, extendedDetailsFilter);
}

int populateRPCTransactionObject(const CTransaction& tx, const uint256& blockHash, UniValue& txobj, std::string filterAddress, bool extendedDetails, std::string extendedDetailsFilter, int blockHeight)
{
    int confirmations = 0;
    int64_t blockTime = 0;
    int positionInBlock = 0;

    if (blockHeight == 0) {
        blockHeight = GetHeight();
    }

    if (!blockHash.IsNull()) {
        CBlockIndex* pBlockIndex = GetBlockIndex(blockHash);
        if (NULL != pBlockIndex) {
            confirmations = 1 + blockHeight - pBlockIndex->nHeight;
            blockTime = pBlockIndex->nTime;
            blockHeight = pBlockIndex->nHeight;
        }
    }

    // attempt to parse the transaction
    CMPTransaction mp_obj;
    int parseRC = ParseTransaction(tx, blockHeight, 0, mp_obj, blockTime);
    if (parseRC < 0) return MP_TX_IS_NOT_ELYSIUM_PROTOCOL;

    const uint256& txid = tx.GetHash();

    // check if we're filtering from listtransactions_MP, and if so whether we have a non-match we want to skip
    if (!filterAddress.empty() && mp_obj.getSender() != filterAddress && mp_obj.getReceiver() != filterAddress) return -1;

    // parse packet and populate mp_obj
    if (!mp_obj.interpret_Transaction()) return MP_TX_IS_NOT_ELYSIUM_PROTOCOL;

    // obtain validity - only confirmed transactions can be valid
    bool valid = false;
    if (confirmations > 0) {
        LOCK(cs_main);
        valid = getValidMPTX(txid);
        positionInBlock = p_ElysiumTXDB->FetchTransactionPosition(txid);
    }

    // populate some initial info for the transaction
    bool fMine = false;
    if (IsMyAddress(mp_obj.getSender()) || IsMyAddress(mp_obj.getReceiver())) fMine = true;
    txobj.push_back(Pair("txid", txid.GetHex()));
    txobj.push_back(Pair("fee", FormatDivisibleMP(mp_obj.getFeePaid())));
    txobj.push_back(Pair("sendingaddress", mp_obj.getSender()));
    if (showRefForTx(mp_obj.getType())) txobj.push_back(Pair("referenceaddress", mp_obj.getReceiver()));
    txobj.push_back(Pair("ismine", fMine));
    txobj.push_back(Pair("version", (uint64_t)mp_obj.getVersion()));
    txobj.push_back(Pair("type_int", (uint64_t)mp_obj.getType()));
    if (mp_obj.getType() != ELYSIUM_TYPE_SIMPLE_SEND) { // Type 0 will add "Type" attribute during populateRPCTypeSimpleSend
        txobj.push_back(Pair("type", mp_obj.getTypeString()));
    }

    // populate type specific info and extended details if requested
    // extended details are not available for unconfirmed transactions
    if (confirmations <= 0) extendedDetails = false;
    populateRPCTypeInfo(mp_obj, txobj, mp_obj.getType(), extendedDetails, extendedDetailsFilter, confirmations);

    // state and chain related information
    if (confirmations != 0 && !blockHash.IsNull()) {
        txobj.push_back(Pair("valid", valid));
        if (!valid) {
            txobj.push_back(Pair("invalidreason", p_ElysiumTXDB->FetchInvalidReason(txid)));
        }
        txobj.push_back(Pair("blockhash", blockHash.GetHex()));
        txobj.push_back(Pair("blocktime", blockTime));
        txobj.push_back(Pair("positioninblock", positionInBlock));
    }
    if (confirmations != 0) {
        txobj.push_back(Pair("block", blockHeight));
    }
    txobj.push_back(Pair("confirmations", confirmations));

    // finished
    return 0;
}

/* Function to call respective populators based on message type
 */
void populateRPCTypeInfo(CMPTransaction& mp_obj, UniValue& txobj, uint32_t txType, bool extendedDetails, std::string extendedDetailsFilter, int confirmations)
{
    switch (txType) {
        case ELYSIUM_TYPE_SIMPLE_SEND:
            populateRPCTypeSimpleSend(mp_obj, txobj);
            break;
        case ELYSIUM_TYPE_LELANTUS_MINT:
            populateRPCTypeLelantusMint(mp_obj, txobj);
            break;
        case ELYSIUM_TYPE_LELANTUS_JOINSPLIT:
            populateRPCTypeLelantusJoinSplit(mp_obj, txobj);
            break;
        case ELYSIUM_TYPE_SEND_TO_OWNERS:
            populateRPCTypeSendToOwners(mp_obj, txobj, extendedDetails, extendedDetailsFilter);
            break;
        case ELYSIUM_TYPE_SEND_ALL:
            populateRPCTypeSendAll(mp_obj, txobj, confirmations);
            break;        
        case ELYSIUM_TYPE_CREATE_PROPERTY_FIXED:
            populateRPCTypeCreatePropertyFixed(mp_obj, txobj, confirmations);
            break;
        case ELYSIUM_TYPE_CREATE_PROPERTY_MANUAL:
            populateRPCTypeCreatePropertyManual(mp_obj, txobj, confirmations);
            break;
        case ELYSIUM_TYPE_GRANT_PROPERTY_TOKENS:
            populateRPCTypeGrant(mp_obj, txobj);
            break;
        case ELYSIUM_TYPE_REVOKE_PROPERTY_TOKENS:
            populateRPCTypeRevoke(mp_obj, txobj);
            break;
        case ELYSIUM_TYPE_CHANGE_ISSUER_ADDRESS:
            populateRPCTypeChangeIssuer(mp_obj, txobj);
            break;
        case ELYSIUM_MESSAGE_TYPE_ACTIVATION:
            populateRPCTypeActivation(mp_obj, txobj);
            break;
    }
}

/* Function to determine whether to display the reference address based on transaction type
 */
bool showRefForTx(uint32_t txType)
{
    switch (txType) {
        case ELYSIUM_TYPE_SIMPLE_SEND: return true;
        case ELYSIUM_TYPE_SEND_TO_OWNERS: return false;
        case ELYSIUM_TYPE_CREATE_PROPERTY_FIXED: return false;
        case ELYSIUM_TYPE_CREATE_PROPERTY_VARIABLE: return false;
        case ELYSIUM_TYPE_CREATE_PROPERTY_MANUAL: return false;
        case ELYSIUM_TYPE_GRANT_PROPERTY_TOKENS: return true;
        case ELYSIUM_TYPE_REVOKE_PROPERTY_TOKENS: return false;
        case ELYSIUM_TYPE_CHANGE_ISSUER_ADDRESS: return true;
        case ELYSIUM_TYPE_SEND_ALL: return true;
        case ELYSIUM_MESSAGE_TYPE_ACTIVATION: return false;
    }
    return true; // default to true, shouldn't be needed but just in case
}

void populateRPCTypeSimpleSend(CMPTransaction& elysiumObj, UniValue& txobj)
{
    uint32_t propertyId = elysiumObj.getProperty();
    int64_t crowdPropertyId = 0, crowdTokens = 0, issuerTokens = 0;
    LOCK(cs_main);
    
    txobj.push_back(Pair("type", "Simple Send"));
    txobj.push_back(Pair("propertyid", (uint64_t)propertyId));
    txobj.push_back(Pair("divisible", isPropertyDivisible(propertyId)));
    txobj.push_back(Pair("amount", FormatMP(propertyId, elysiumObj.getAmount())));
    
}

void populateRPCTypeLelantusMint(CMPTransaction& elysiumObj, UniValue& txobj)
{
    uint32_t propertyId = elysiumObj.getProperty();
    txobj.push_back(Pair("propertyid", (uint64_t)propertyId));
    txobj.push_back(Pair("divisible", isPropertyDivisible(propertyId)));
    txobj.push_back(Pair("amount", FormatMP(propertyId, elysiumObj.getLelantusMintValue())));

}

void populateRPCTypeLelantusJoinSplit(CMPTransaction& elysiumObj, UniValue& txobj)
{
    uint32_t propertyId = elysiumObj.getProperty();
    txobj.push_back(Pair("propertyid", (uint64_t)propertyId));
    txobj.push_back(Pair("divisible", isPropertyDivisible(propertyId)));
    txobj.push_back(Pair("amount", FormatMP(propertyId, elysiumObj.getLelantusSpendAmount())));

}

void populateRPCTypeSendToOwners(CMPTransaction& elysiumObj, UniValue& txobj, bool extendedDetails, std::string extendedDetailsFilter)
{
    uint32_t propertyId = elysiumObj.getProperty();
    txobj.push_back(Pair("propertyid", (uint64_t)propertyId));
    txobj.push_back(Pair("divisible", isPropertyDivisible(propertyId)));
    txobj.push_back(Pair("amount", FormatMP(propertyId, elysiumObj.getAmount())));
    if (extendedDetails) populateRPCExtendedTypeSendToOwners(elysiumObj.getHash(), extendedDetailsFilter, txobj, elysiumObj.getVersion());
}

void populateRPCTypeSendAll(CMPTransaction& elysiumObj, UniValue& txobj, int confirmations)
{
    UniValue subSends(UniValue::VARR);
    if (elysiumObj.getEcosystem() == 1) txobj.push_back(Pair("ecosystem", "main"));
    if (elysiumObj.getEcosystem() == 2) txobj.push_back(Pair("ecosystem", "test"));
    if (confirmations > 0) {
        if (populateRPCSendAllSubSends(elysiumObj.getHash(), subSends) > 0) txobj.push_back(Pair("subsends", subSends));
    }
}

void populateRPCTypeCreatePropertyFixed(CMPTransaction& elysiumObj, UniValue& txobj, int confirmations)
{
    LOCK(cs_main);
    if (confirmations > 0) {
        uint32_t propertyId = _my_sps->findSPByTX(elysiumObj.getHash());
        if (propertyId > 0) {
            txobj.push_back(Pair("propertyid", (uint64_t) propertyId));
            txobj.push_back(Pair("divisible", isPropertyDivisible(propertyId)));
        }
    }
    txobj.push_back(Pair("ecosystem", strEcosystem(elysiumObj.getEcosystem())));
    txobj.push_back(Pair("propertytype", strPropertyType(elysiumObj.getPropertyType())));
    txobj.push_back(Pair("category", elysiumObj.getSPCategory()));
    txobj.push_back(Pair("subcategory", elysiumObj.getSPSubCategory()));
    txobj.push_back(Pair("propertyname", elysiumObj.getSPName()));
    txobj.push_back(Pair("data", elysiumObj.getSPData()));
    txobj.push_back(Pair("url", elysiumObj.getSPUrl()));
    std::string strAmount = FormatByType(elysiumObj.getAmount(), elysiumObj.getPropertyType());
    txobj.push_back(Pair("amount", strAmount));
}

void populateRPCTypeCreatePropertyManual(CMPTransaction& elysiumObj, UniValue& txobj, int confirmations)
{
    LOCK(cs_main);
    if (confirmations > 0) {
        uint32_t propertyId = _my_sps->findSPByTX(elysiumObj.getHash());
        if (propertyId > 0) {
            txobj.push_back(Pair("propertyid", (uint64_t) propertyId));
            txobj.push_back(Pair("divisible", isPropertyDivisible(propertyId)));
        }
    }
    txobj.push_back(Pair("propertytype", strPropertyType(elysiumObj.getPropertyType())));
    txobj.push_back(Pair("ecosystem", strEcosystem(elysiumObj.getEcosystem())));
    txobj.push_back(Pair("category", elysiumObj.getSPCategory()));
    txobj.push_back(Pair("subcategory", elysiumObj.getSPSubCategory()));
    txobj.push_back(Pair("propertyname", elysiumObj.getSPName()));
    txobj.push_back(Pair("data", elysiumObj.getSPData()));
    txobj.push_back(Pair("url", elysiumObj.getSPUrl()));
    std::string strAmount = FormatByType(0, elysiumObj.getPropertyType());
    txobj.push_back(Pair("amount", strAmount)); // managed token creations don't issue tokens with the create tx
}

void populateRPCTypeCloseCrowdsale(CMPTransaction& elysiumObj, UniValue& txobj)
{
    uint32_t propertyId = elysiumObj.getProperty();
    txobj.push_back(Pair("propertyid", (uint64_t)propertyId));
    txobj.push_back(Pair("divisible", isPropertyDivisible(propertyId)));
}

void populateRPCTypeGrant(CMPTransaction& elysiumObj, UniValue& txobj)
{
    uint32_t propertyId = elysiumObj.getProperty();
    txobj.push_back(Pair("propertyid", (uint64_t)propertyId));
    txobj.push_back(Pair("divisible", isPropertyDivisible(propertyId)));
    txobj.push_back(Pair("amount", FormatMP(propertyId, elysiumObj.getAmount())));
}

void populateRPCTypeRevoke(CMPTransaction& elysiumObj, UniValue& txobj)
{
    uint32_t propertyId = elysiumObj.getProperty();
    txobj.push_back(Pair("propertyid", (uint64_t)propertyId));
    txobj.push_back(Pair("divisible", isPropertyDivisible(propertyId)));
    txobj.push_back(Pair("amount", FormatMP(propertyId, elysiumObj.getAmount())));
}

void populateRPCTypeChangeIssuer(CMPTransaction& elysiumObj, UniValue& txobj)
{
    uint32_t propertyId = elysiumObj.getProperty();
    txobj.push_back(Pair("propertyid", (uint64_t)propertyId));
    txobj.push_back(Pair("divisible", isPropertyDivisible(propertyId)));
}

void populateRPCTypeActivation(CMPTransaction& elysiumObj, UniValue& txobj)
{
    txobj.push_back(Pair("featureid", (uint64_t) elysiumObj.getFeatureId()));
    txobj.push_back(Pair("activationblock", (uint64_t) elysiumObj.getActivationBlock()));
    txobj.push_back(Pair("minimumversion", (uint64_t) elysiumObj.getMinClientVersion()));
}

void populateRPCExtendedTypeSendToOwners(const uint256 txid, std::string extendedDetailsFilter, UniValue& txobj, uint16_t version)
{
    UniValue receiveArray(UniValue::VARR);
    uint64_t tmpAmount = 0, stoFee = 0, numRecipients = 0;
    LOCK(cs_main);
    s_stolistdb->getRecipients(txid, extendedDetailsFilter, &receiveArray, &tmpAmount, &numRecipients);
    if (version == MP_TX_PKT_V0) {
        stoFee = numRecipients * TRANSFER_FEE_PER_OWNER;
    } else {
        stoFee = numRecipients * TRANSFER_FEE_PER_OWNER_V1;
    }
    txobj.push_back(Pair("totalstofee", FormatDivisibleMP(stoFee))); // fee always ELYSIUM so always divisible
    txobj.push_back(Pair("recipients", receiveArray));
}

/* Function to enumerate sub sends for a given txid and add to supplied JSON array
 * Note: this function exists as send all has the potential to carry multiple sends in a single transaction.
 */
int populateRPCSendAllSubSends(const uint256& txid, UniValue& subSends)
{
    int numberOfSubSends = 0;
    {
        LOCK(cs_main);
        numberOfSubSends = p_txlistdb->getNumberOfSubRecords(txid);
    }
    if (numberOfSubSends <= 0) {
        PrintToLog("TXLISTDB Error: Transaction %s parsed as a send all but could not locate sub sends in txlistdb.\n", txid.GetHex());
        return -1;
    }
    for (int subSend = 1; subSend <= numberOfSubSends; subSend++) {
        UniValue subSendObj(UniValue::VOBJ);
        uint32_t propertyId;
        int64_t amount;
        {
            LOCK(cs_main);
            p_txlistdb->getSendAllDetails(txid, subSend, propertyId, amount);
        }
        subSendObj.push_back(Pair("propertyid", (uint64_t)propertyId));
        subSendObj.push_back(Pair("divisible", isPropertyDivisible(propertyId)));
        subSendObj.push_back(Pair("amount", FormatMP(propertyId, amount)));
        subSends.push_back(subSendObj);
    }
    return subSends.size();
}

/* Function to enumerate DEx purchases for a given txid and add to supplied JSON array
 * Note: this function exists as it is feasible for a single transaction to carry multiple outputs
 *       and thus make multiple purchases from a single transaction
 */
int populateRPCDExPurchases(const CTransaction& wtx, UniValue& purchases, std::string filterAddress)
{
    int numberOfPurchases = 0;
    {
        LOCK(cs_main);
        numberOfPurchases = p_txlistdb->getNumberOfSubRecords(wtx.GetHash());
    }
    if (numberOfPurchases <= 0) {
        PrintToLog("TXLISTDB Error: Transaction %s parsed as a DEx payment but could not locate purchases in txlistdb.\n", wtx.GetHash().GetHex());
        return -1;
    }
    for (int purchaseNumber = 1; purchaseNumber <= numberOfPurchases; purchaseNumber++) {
        UniValue purchaseObj(UniValue::VOBJ);
        std::string buyer, seller;
        uint64_t vout, nValue, propertyId;
        {
            LOCK(cs_main);
            p_txlistdb->getPurchaseDetails(wtx.GetHash(), purchaseNumber, &buyer, &seller, &vout, &propertyId, &nValue);
        }
        if (!filterAddress.empty() && buyer != filterAddress && seller != filterAddress) continue; // filter requested & doesn't match
        bool bIsMine = false;
        if (IsMyAddress(buyer) || IsMyAddress(seller)) bIsMine = true;
        int64_t amountPaid = wtx.vout[vout].nValue;
        purchaseObj.push_back(Pair("vout", vout));
        purchaseObj.push_back(Pair("amountpaid", FormatDivisibleMP(amountPaid)));
        purchaseObj.push_back(Pair("ismine", bIsMine));
        purchaseObj.push_back(Pair("referenceaddress", seller));
        purchaseObj.push_back(Pair("propertyid", propertyId));
        purchaseObj.push_back(Pair("amountbought", FormatDivisibleMP(nValue)));
        purchaseObj.push_back(Pair("valid", true)); //only valid purchases are stored, anything else is regular BTC tx
        purchases.push_back(purchaseObj);
    }
    return purchases.size();
}
