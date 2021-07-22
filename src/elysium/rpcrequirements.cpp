#include "rpcrequirements.h"

#include "elysium.h"
#include "rules.h"
#include "sp.h"
#include "utilsbitcoin.h"

#include "../amount.h"
#include "../validation.h"
#include "../rpc/protocol.h"
#include "../sync.h"
#include "../tinyformat.h"

#include <string>

#include <stdint.h>

void RequireBalance(const std::string& address, uint32_t propertyId, int64_t amount)
{
    int64_t balance = getMPbalance(address, propertyId, BALANCE);
    if (balance < amount) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Sender has insufficient balance");
    }
    int64_t balanceUnconfirmed = getUserAvailableMPbalance(address, propertyId);
    if (balanceUnconfirmed < amount) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Sender has insufficient balance (due to pending transactions)");
    }
}

void RequirePrimaryToken(uint32_t propertyId)
{
    if (propertyId < 1 || 2 < propertyId) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Property identifier must be 1 (ELYSIUM) or 2 (TELYSIUM)");
    }
}

void RequirePropertyName(const std::string& name)
{
    if (name.empty()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Property name must not be empty");
    }
}

void RequireExistingProperty(uint32_t propertyId)
{
    LOCK(cs_main);
    if (!elysium::IsPropertyIdValid(propertyId)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Property identifier does not exist");
    }
}

void RequireSameEcosystem(uint32_t propertyId, uint32_t otherId)
{
    if (elysium::isTestEcosystemProperty(propertyId) != elysium::isTestEcosystemProperty(otherId)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Properties must be in the same ecosystem");
    }
}

void RequireDifferentIds(uint32_t propertyId, uint32_t otherId)
{
    if (propertyId == otherId) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Property identifiers must not be the same");
    }
}


void RequireManagedProperty(uint32_t propertyId)
{
    LOCK(cs_main);
    CMPSPInfo::Entry sp;
    if (!elysium::_my_sps->getSP(propertyId, sp)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to retrieve property");
    }
    if (sp.fixed || !sp.manual) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Property identifier does not refer to a managed property");
    }
}

void RequireTokenIssuer(const std::string& address, uint32_t propertyId)
{
    LOCK(cs_main);
    CMPSPInfo::Entry sp;
    if (!elysium::_my_sps->getSP(propertyId, sp)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Failed to retrieve property");
    }
    if (address != sp.issuer) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Sender is not authorized to manage the property");
    }
}


void RequireSaneReferenceAmount(int64_t amount)
{
    if ((0.01 * COIN) < amount) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Reference amount higher is than 0.01 FIRO");
    }
}


void RequireHeightInChain(int blockHeight)
{
    if (blockHeight < 0 || elysium::GetHeight() < blockHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height is out of range");
    }
}

void RequireLelantusStatus(elysium::LelantusStatus status)
{
    if (!elysium::IsLelantusStatusValid(status)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Lelantus status is not valid");
    }

    if (!elysium::IsFeatureActivated(elysium::FEATURE_LELANTUS, elysium::GetHeight())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Lelantus feature is not activated yet");
    }
}

namespace elysium {

void RequireLelantus(PropertyId property)
{
    if (!IsFeatureActivated(FEATURE_LELANTUS, GetHeight())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Lelantus feature is not activated yet");
    }

    if (!IsLelantusEnabled(property)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Property has not enabled Lelantus");
    }
}

}
