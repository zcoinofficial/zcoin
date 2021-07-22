#ifndef ELYSIUM_CONSENSUSHASH_H
#define ELYSIUM_CONSENSUSHASH_H

#include "uint256.h"

namespace elysium
{
/** Checks if a given block should be consensus hashed. */
bool ShouldConsensusHashBlock(int block);

/** Obtains a hash of all balances to use for consensus verification and checkpointing. */
uint256 GetConsensusHash();

/** Obtains a hash of the balances for a specific property. */
uint256 GetBalancesHash(const uint32_t hashPropertyId);

} // namespace elysium

#endif // ELYSIUM_CONSENSUSHASH_H
