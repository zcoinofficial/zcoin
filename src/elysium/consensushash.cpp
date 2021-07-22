/**
 * @file consensushash.cpp
 *
 * This file contains the function to generate consensus hashes.
 */

#include "elysium/consensushash.h"
#include "elysium/log.h"
#include "elysium/elysium.h"
#include "elysium/parse_string.h"
#include "elysium/sp.h"

#include "arith_uint256.h"
#include "uint256.h"

#include <stdint.h>
#include <algorithm>
#include <string>
#include <vector>

#include <openssl/sha.h>

namespace elysium
{
bool ShouldConsensusHashBlock(int block) {
    if (elysium_debug_consensus_hash_every_block) {
        return true;
    }

    if (!mapMultiArgs.count("-elysiumshowblockconsensushash")) {
        return false;
    }

    const std::vector<std::string>& vecBlocks = mapMultiArgs.at("-elysiumshowblockconsensushash");
    for (std::vector<std::string>::const_iterator it = vecBlocks.begin(); it != vecBlocks.end(); ++it) {
        int64_t paramBlock = StrToInt64(*it, false);
        if (paramBlock < 1) continue; // ignore non numeric values
        if (paramBlock == block) {
            return true;
        }
    }

    return false;
}

// Generates a consensus string for hashing based on a tally object
std::string GenerateConsensusString(const CMPTally& tallyObj, const std::string& address, const uint32_t propertyId)
{
    int64_t balance = tallyObj.getMoney(propertyId, BALANCE);

    // return a blank string if all balances are empty
    if (!balance) return "";

    return strprintf("%s|%d|%d",
            address, propertyId, balance);
}

// Generates a consensus string for hashing based on a property issuer
std::string GenerateConsensusString(const uint32_t propertyId, const std::string& address)
{
    return strprintf("%d|%s", propertyId, address);
}

/**
 * Obtains a hash of the active state to use for consensus verification and checkpointing.
 *
 * For increased flexibility, so other implementations like OmniWallet and OmniChest can
 * also apply this methodology without necessarily using the same exact data types (which
 * would be needed to hash the data bytes directly), create a string in the following
 * format for each entry to use for hashing:
 *
 * ---STAGE 1 - BALANCES---
 * Format specifiers & placeholders:
 *   "%s|%d|%d" - "address|propertyid|balance"
 *
 * Note: empty balance records and the pending tally are ignored. Addresses are sorted based
 * on lexicographical order, and balance records are sorted by the property identifiers.
 *
 *
 * Note: ordered by property ID.
 *
 * ---STAGE 6 - PROPERTIES---
 * Format specifiers & placeholders:
 *   "%d|%s" - "propertyid|issueraddress"
 *
 * Note: ordered by property ID.
 *
 * The byte order is important, and we assume:
 *   SHA256("abc") = "ad1500f261ff10b49c7a1796a36103b02322ae5dde404141eacf018fbf1678ba"
 *
 */
uint256 GetConsensusHash()
{
    // allocate and init a SHA256_CTX
    SHA256_CTX shaCtx;
    SHA256_Init(&shaCtx);

    LOCK(cs_main);

    if (elysium_debug_consensus_hash) PrintToLog("Beginning generation of current consensus hash...\n");

    // Balances - loop through the tally map, updating the sha context with the data from each balance and tally type
    // Placeholders:  "address|propertyid|balance|selloffer_reserve|accept_reserve|metadex_reserve"
    // Sort alphabetically first
    std::map<std::string, CMPTally> tallyMapSorted;
    for (std::unordered_map<string, CMPTally>::iterator uoit = mp_tally_map.begin(); uoit != mp_tally_map.end(); ++uoit) {
        tallyMapSorted.insert(std::make_pair(uoit->first,uoit->second));
    }
    for (std::map<string, CMPTally>::iterator my_it = tallyMapSorted.begin(); my_it != tallyMapSorted.end(); ++my_it) {
        const std::string& address = my_it->first;
        CMPTally& tally = my_it->second;
        tally.init();
        uint32_t propertyId = 0;
        while (0 != (propertyId = (tally.next()))) {
            std::string dataStr = GenerateConsensusString(tally, address, propertyId);
            if (dataStr.empty()) continue; // skip empty balances
            if (elysium_debug_consensus_hash) PrintToLog("Adding balance data to consensus hash: %s\n", dataStr);
            SHA256_Update(&shaCtx, dataStr.c_str(), dataStr.length());
        }
    }

    // Properties - loop through each property and store the issuer (to capture state changes via change issuer transactions)
    // Note: we are loading every SP from the DB to check the issuer, if using consensus_hash_every_block debug option this
    //       will slow things down dramatically.  Not an issue to do it once every 10,000 blocks for checkpoint verification.
    // Placeholders: "propertyid|issueraddress"
    for (uint8_t ecosystem = 1; ecosystem <= 2; ecosystem++) {
        uint32_t startPropertyId = (ecosystem == 1) ? 1 : TEST_ECO_PROPERTY_1;
        for (uint32_t propertyId = startPropertyId; propertyId < _my_sps->peekNextSPID(ecosystem); propertyId++) {
            CMPSPInfo::Entry sp;
            if (!_my_sps->getSP(propertyId, sp)) {
                PrintToLog("Error loading property ID %d for consensus hashing, hash should not be trusted!\n");
                continue;
            }
            std::string dataStr = GenerateConsensusString(propertyId, sp.issuer);
            if (elysium_debug_consensus_hash) PrintToLog("Adding property to consensus hash: %s\n", dataStr);
            SHA256_Update(&shaCtx, dataStr.c_str(), dataStr.length());
        }
    }

    // extract the final result and return the hash
    uint256 consensusHash;
    SHA256_Final((unsigned char*)&consensusHash, &shaCtx);
    if (elysium_debug_consensus_hash) PrintToLog("Finished generation of consensus hash.  Result: %s\n", consensusHash.GetHex());

    return consensusHash;
}

/** Obtains a hash of the balances for a specific property. */
uint256 GetBalancesHash(const uint32_t hashPropertyId)
{
    SHA256_CTX shaCtx;
    SHA256_Init(&shaCtx);

    LOCK(cs_main);

    std::map<std::string, CMPTally> tallyMapSorted;
    for (std::unordered_map<string, CMPTally>::iterator uoit = mp_tally_map.begin(); uoit != mp_tally_map.end(); ++uoit) {
        tallyMapSorted.insert(std::make_pair(uoit->first,uoit->second));
    }
    for (std::map<string, CMPTally>::iterator my_it = tallyMapSorted.begin(); my_it != tallyMapSorted.end(); ++my_it) {
        const std::string& address = my_it->first;
        CMPTally& tally = my_it->second;
        tally.init();
        uint32_t propertyId = 0;
        while (0 != (propertyId = (tally.next()))) {
            if (propertyId != hashPropertyId) continue;
            std::string dataStr = GenerateConsensusString(tally, address, propertyId);
            if (dataStr.empty()) continue;
            if (elysium_debug_consensus_hash) PrintToLog("Adding data to balances hash: %s\n", dataStr);
            SHA256_Update(&shaCtx, dataStr.c_str(), dataStr.length());
        }
    }

    uint256 balancesHash;
    SHA256_Final((unsigned char*)&balancesHash, &shaCtx);

    return balancesHash;
}

} // namespace elysium
