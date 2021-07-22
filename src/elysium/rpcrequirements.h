#ifndef FIRO_ELYSIUM_RPCREQUIREMENTS_H
#define FIRO_ELYSIUM_RPCREQUIREMENTS_H

#include "property.h"

#include <stdint.h>
#include <string>
using namespace elysium;

void RequireBalance(const std::string& address, uint32_t propertyId, int64_t amount);
void RequirePrimaryToken(uint32_t propertyId);
void RequirePropertyName(const std::string& name);
void RequireExistingProperty(uint32_t propertyId);
void RequireSameEcosystem(uint32_t propertyId, uint32_t otherId);
void RequireDifferentIds(uint32_t propertyId, uint32_t otherId);
void RequireManagedProperty(uint32_t propertyId);
void RequireTokenIssuer(const std::string& address, uint32_t propertyId);
void RequireSaneReferenceAmount(int64_t amount);
void RequireHeightInChain(int blockHeight);
void RequireLelantusStatus(elysium::LelantusStatus status);

namespace elysium {

	void RequireLelantus(PropertyId property);

}

#endif // FIRO_ELYSIUM_RPCREQUIREMENTS_H
