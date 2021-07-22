/* ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
 * Copyright 2019 Pawel Bylica.
 * Licensed under the Apache License, Version 2.0.
 */

#pragma once
#ifndef CRYPTO_PROGPOW_VERSION_HPP_
#define CRYPTO_PROGPOW_VERSION_HPP_

/** The ethash library version. */
#define ETHASH_VERSION "0.5.2"

#ifdef __cplusplus
namespace ethash
{
/// The ethash library version.
constexpr auto version = ETHASH_VERSION;

}  // namespace ethash
#endif
#endif // !CRYPTO_PROGPOW_VERSION_HPP_