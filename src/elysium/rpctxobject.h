#ifndef ELYSIUM_RPCTXOBJECT_H
#define ELYSIUM_RPCTXOBJECT_H

#include <univalue.h>

#include <string>

class uint256;
class CMPTransaction;
class CTransaction;

int populateRPCTransactionObject(const uint256& txid, UniValue& txobj, std::string filterAddress = "", bool extendedDetails = false, std::string extendedDetailsFilter = "");
int populateRPCTransactionObject(const CTransaction& tx, const uint256& blockHash, UniValue& txobj, std::string filterAddress = "", bool extendedDetails = false, std::string extendedDetailsFilter = "", int blockHeight = 0);

void populateRPCTypeInfo(CMPTransaction& mp_obj, UniValue& txobj, uint32_t txType, bool extendedDetails, std::string extendedDetailsFilter, int confirmations);

void populateRPCTypeSimpleSend(CMPTransaction& elysiumObj, UniValue& txobj);
void populateRPCTypeLelantusMint(CMPTransaction& elysiumObj, UniValue& txobj);
void populateRPCTypeLelantusJoinSplit(CMPTransaction& elysiumObj, UniValue& txobj);
void populateRPCTypeSendToOwners(CMPTransaction& elysiumObj, UniValue& txobj, bool extendedDetails, std::string extendedDetailsFilter);
void populateRPCTypeSendAll(CMPTransaction& elysiumObj, UniValue& txobj, int confirmations);
void populateRPCTypeCreatePropertyFixed(CMPTransaction& elysiumObj, UniValue& txobj, int confirmations);
void populateRPCTypeCreatePropertyManual(CMPTransaction& elysiumObj, UniValue& txobj, int confirmations);
void populateRPCTypeCloseCrowdsale(CMPTransaction& elysiumObj, UniValue& txobj);
void populateRPCTypeGrant(CMPTransaction& elysiumObj, UniValue& txobj);
void populateRPCTypeRevoke(CMPTransaction& elysiumObj, UniValue& txobj);
void populateRPCTypeChangeIssuer(CMPTransaction& elysiumObj, UniValue& txobj);
void populateRPCTypeActivation(CMPTransaction& elysiumObj, UniValue& txobj);

void populateRPCExtendedTypeSendToOwners(const uint256 txid, std::string extendedDetailsFilter, UniValue& txobj, uint16_t version);
int populateRPCSendAllSubSends(const uint256& txid, UniValue& subSends);

bool showRefForTx(uint32_t txType);

#endif // ELYSIUM_RPCTXOBJECT_H
