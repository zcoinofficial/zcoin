# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1 univalue tor bls-signatures
SUBDIRS = tor bls-signatures

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
AM_LIBTOOLFLAGS = --preserve-dup-deps
EXTRA_LIBRARIES =

if ENABLE_CRASH_HOOKS
if CRASH_HOOKS_WRAPPED_CXX_ABI
# Wrap internal C++ ABI's so that we can attach stacktraces to exceptions
LDFLAGS_WRAP_EXCEPTIONS = -Wl,-wrap,__cxa_allocate_exception -Wl,-wrap,__cxa_free_exception
if TARGET_WINDOWS
LDFLAGS_WRAP_EXCEPTIONS += -Wl,-wrap,_assert -Wl,-wrap,_wassert
else
LDFLAGS_WRAP_EXCEPTIONS += -Wl,-wrap,__assert_fail
endif
endif

if TARGET_WINDOWS
BACKTRACE_LIB = -ldbghelp -lbacktrace
else
BACKTRACE_LIB = -lbacktrace
endif
endif

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

TOR_LIBS = tor/src/core/libtor-app.a \
    tor/src/lib/libtor-meminfo.a \
    tor/src/lib/libtor-term.a \
    tor/src/lib/libtor-osinfo.a \
    tor/src/lib/libtor-geoip.a \
    tor/src/lib/libtor-math.a \
    tor/src/lib/libtor-tls.a \
    tor/src/lib/libtor-process.a \
    tor/src/lib/libtor-evloop.a \
    tor/src/lib/libtor-thread.a \
    tor/src/lib/libtor-compress.a \
    @LIBZSTD@ \
    tor/src/lib/libtor-net.a \
    tor/src/lib/libtor-buf.a \
    tor/src/lib/libtor-time.a \
    tor/src/lib/libtor-err.a \
    tor/src/lib/libtor-log.a \
    tor/src/lib/libtor-version.a \
    tor/src/lib/libtor-pubsub.a \
    tor/src/lib/libtor-dispatch.a \
    tor/src/lib/libtor-confmgt.a \
    tor/src/lib/libtor-container.a \
    tor/src/lib/libtor-crypt-ops.a \
    tor/src/lib/libtor-fs.a \
    tor/src/lib/libtor-fdio.a \
    tor/src/lib/libtor-sandbox.a \
    tor/src/lib/libtor-memarea.a \
    tor/src/lib/libtor-intmath.a \
    tor/src/lib/libtor-encoding.a \
    tor/src/lib/libtor-smartlist-core.a \
    tor/src/lib/libtor-lock.a \
    tor/src/lib/libtor-wallclock.a \
    tor/src/lib/libtor-string.a \
    tor/src/lib/libtor-malloc.a \
	tor/src/lib/libtor-ctime.a \
	tor/src/trunnel/libor-trunnel.a \
	tor/src/lib/libcurve25519_donna.a \
	tor/src/ext/ed25519/donna/libed25519_donna.a \
	tor/src/ext/ed25519/ref10/libed25519_ref10.a \
	tor/src/ext/keccak-tiny/libkeccak-tiny.a

tor.timestamp: $(wildcard tor/src/core/or/*.c) $(wildcard tor/src/core/or/*.h) \
		$(wildcard tor/src/lib/*.c) $(wildcard tor/src/lib/*.h) \
		$(wildcard tor/src/trunnel/*.c) $(wildcard tor/src/trunnel/*.h) \
		$(wildcard tor/src/ext/*.c) $(wildcard tor/src/ext/*.h)
	@rm -f tor.timestamp.tmp
	@touch tor.timestamp.tmp
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C tor
	@mv -f tor.timestamp.tmp tor.timestamp

$(TOR_LIBS): tor.timestamp
	@if test -f $@; then :; else \
		rm -f tor.timestamp; \
		$(MAKE) $(AM_MAKEFLAGS) tor.timestamp; \
	fi

LIBBLSSIG_INCLUDES=-I./bls-signatures/build/contrib/relic/include -I./bls-signatures/contrib/relic/include
LIBBLSSIG_LIBS=bls-signatures/build/libchiabls.a
LIBBLSSIG_DEPENDS=-lgmp

$(LIBBLSSIG_LIBS): $(wildcard bls-signatures/src/*.cpp) $(wildcard bls-signatures/src/*.hpp)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C bls-signatures/build

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/src
BITCOIN_INCLUDES += $(UNIVALUE_CFLAGS)

LIBBITCOIN_SERVER=libbitcoin_server.a
LIBBITCOIN_COMMON=libbitcoin_common.a
LIBBITCOIN_CONSENSUS=libbitcoin_consensus.a
LIBBITCOIN_CLI=libbitcoin_cli.a
LIBBITCOIN_UTIL=libbitcoin_util.a
LIBLELANTUS=liblelantus.a
LIBBITCOIN_CRYPTO=crypto/libbitcoin_crypto.a
LIBBITCOINQT=qt/libfiroqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la

LIBFIRO_SIGMA=libsigma.a

if ENABLE_ZMQ
LIBBITCOIN_ZMQ=libbitcoin_zmq.a
endif
if BUILD_BITCOIN_LIBS
LIBBITCOINCONSENSUS=libbitcoinconsensus.la
endif
if ENABLE_WALLET
LIBBITCOIN_WALLET=libbitcoin_wallet.a
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_CONSENSUS) \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_CLI) \
  $(LIBBITCOIN_WALLET) \
  $(LIBBITCOIN_ZMQ) \
  $(LIBFIRO_SIGMA) \
  $(LIBLELANTUS)

lib_LTLIBRARIES = $(LIBBITCOINCONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_BITCOIND
  bin_PROGRAMS += firod
endif

if BUILD_BITCOIN_UTILS
  bin_PROGRAMS += firo-cli firo-tx
endif

.PHONY: FORCE check-symbols check-security
# bitcoin core #
BITCOIN_CORE_H = \
  activemasternode.h \
  addressindex.h \
  spentindex.h \
  addrdb.h \
  addrman.h \
  base58.h \
  batchedlogger.h \
  bloom.h \
  blockencodings.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  ctpl.h \
  cxxtimer.hpp \
  evo/cbtx.h \
  evo/deterministicmns.h \
  evo/evodb.h \
  evo/mnauth.h \
  evo/providertx.h \
  evo/simplifiedmns.h \
  evo/specialtx.h \
  evo/spork.h \
  dsnotificationinterface.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  fs.h \
  httprpc.h \
  httpserver.h \
  indirectmap.h \
  init.h \
  key.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  threadinterrupt.h \
  masternode-utils.h \
  mbstring.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_processing.h \
  netaddress.h \
  netbase.h \
  netfulfilledman.h \
  netmessagemaker.h \
  noui.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  primitives/mint_spend.h \
  fixed.h \
  pow.h \
  hdmint/hdmint.h \
  protocol.h \
  random.h \
  reverselock.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/server.h \
  rpc/register.h \
  scheduler.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  script/ismine.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/allocators/pooled_secure.h \
  support/allocators/mt_pooled_secure.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utiltime.h \
  batchproof_container.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  wallet/coincontrol.h \
  wallet/mnemoniccontainer.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/rpcwallet.h \
  wallet/sigmaspendbuilder.h \
  wallet/txbuilder.h \
  wallet/lelantusjoinsplitbuilder.h \
  wallet/wallet.h \
  wallet/walletexcept.h \
  wallet/walletdb.h \
  wallet/authhelper.h \
  wallet/bip39.h \
  wallet/bip39_english.h \
  definition.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h \
  hdmint/mintpool.h \
  hdmint/tracker.h \
  hdmint/wallet.h \
  bip47/defs.h \
  bip47/account.h \
  bip47/paymentchannel.h \
  bip47/bip47utils.h \
  bip47/paymentcode.h \
  bip47/secretpoint.h \
  sigma.h \
  lelantus.h \
  blacklists.h \
  coin_containers.h \
  firo_params.h \
  addresstype.h \
  mtpstate.h \
  messagesigner.h \
  masternode-payments.h \
  masternode-sync.h \
  saltedhasher.h \
  unordered_lru_cache.h \
  llmq/quorums.h \
  llmq/quorums_blockprocessor.h \
  llmq/quorums_dkgsessionmgr.h \
  llmq/quorums_commitment.h \
  llmq/quorums_signing.h \
  llmq/quorums_dkgsessionhandler.h \
  llmq/quorums_dkgsession.h \
  llmq/quorums_instantsend.h \
  llmq/quorums_debug.h \
  llmq/quorums_utils.h \
  llmq/quorums_chainlocks.h\
  llmq/quorums_init.h \
  llmq/quorums_signing_shares.h \
  immer/atom.hpp \
  immer/set.hpp \
  immer/box.hpp \
  immer/flex_vector_transient.hpp \
  immer/transience/no_transience_policy.hpp \
  immer/transience/gc_transience_policy.hpp \
  immer/map_transient.hpp \
  immer/set_transient.hpp \
  immer/flex_vector.hpp \
  immer/refcount/enable_intrusive_ptr.hpp \
  immer/refcount/no_refcount_policy.hpp \
  immer/refcount/unsafe_refcount_policy.hpp \
  immer/refcount/refcount_policy.hpp \
  immer/memory_policy.hpp \
  immer/config.hpp \
  immer/array.hpp \
  immer/vector.hpp \
  immer/detail/arrays/no_capacity.hpp \
  immer/detail/arrays/node.hpp \
  immer/detail/arrays/with_capacity.hpp \
  immer/detail/type_traits.hpp \
  immer/detail/rbts/rbtree_iterator.hpp \
  immer/detail/rbts/rbtree.hpp \
  immer/detail/rbts/rrbtree.hpp \
  immer/detail/rbts/visitor.hpp \
  immer/detail/rbts/position.hpp \
  immer/detail/rbts/bits.hpp \
  immer/detail/rbts/node.hpp \
  immer/detail/rbts/operations.hpp \
  immer/detail/rbts/rrbtree_iterator.hpp \
  immer/detail/combine_standard_layout.hpp \
  immer/detail/ref_count_base.hpp \
  immer/detail/hamts/champ_iterator.hpp \
  immer/detail/hamts/champ.hpp \
  immer/detail/hamts/bits.hpp \
  immer/detail/hamts/node.hpp \
  immer/detail/util.hpp \
  immer/detail/iterator_facade.hpp \
  immer/vector_transient.hpp \
  immer/experimental/dvektor.hpp \
  immer/experimental/detail/dvektor_impl.hpp \
  immer/heap/free_list_heap.hpp \
  immer/heap/tags.hpp \
  immer/heap/debug_size_heap.hpp \
  immer/heap/heap_policy.hpp \
  immer/heap/gc_heap.hpp \
  immer/heap/unsafe_free_list_heap.hpp \
  immer/heap/split_heap.hpp \
  immer/heap/identity_heap.hpp \
  immer/heap/thread_local_free_list_heap.hpp \
  immer/heap/malloc_heap.hpp \
  immer/heap/cpp_heap.hpp \
  immer/heap/free_list_node.hpp \
  immer/heap/with_data.hpp \
  immer/algorithm.hpp \
  immer/array_transient.hpp \
  immer/map.hpp

obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libbitcoin_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between firod and firo-qt
libbitcoin_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(LIBBLSSIG_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libbitcoin_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_server_a_SOURCES = \
  addrman.cpp \
  addrdb.cpp \
  batchedlogger.cpp \
  bloom.cpp \
  blockencodings.cpp \
  chain.cpp \
  checkpoints.cpp \
  dsnotificationinterface.cpp \
  evo/cbtx.cpp \
  evo/deterministicmns.cpp \
  evo/evodb.cpp \
  evo/mnauth.cpp \
  evo/providertx.cpp \
  evo/simplifiedmns.cpp \
  evo/specialtx.cpp \
  evo/spork.cpp \
  llmq/quorums.cpp \
  llmq/quorums_blockprocessor.cpp \
  llmq/quorums_commitment.cpp \
  llmq/quorums_chainlocks.cpp \
  llmq/quorums_debug.cpp \
  llmq/quorums_dkgsessionhandler.cpp \
  llmq/quorums_dkgsessionmgr.cpp \
  llmq/quorums_dkgsession.cpp \
  llmq/quorums_init.cpp \
  llmq/quorums_instantsend.cpp \
  llmq/quorums_signing.cpp \
  llmq/quorums_signing_shares.cpp \
  llmq/quorums_utils.cpp \
  masternode-payments.cpp \
  masternode-sync.cpp \
  masternode-utils.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  dbwrapper.cpp \
  threadinterrupt.cpp \
  merkleblock.cpp \
  miner.cpp \
  messagesigner.cpp \
  net.cpp \
  netfulfilledman.cpp \
  net_processing.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  primitives/mint_spend.cpp \
  pow.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/masternode.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  rpc/rpcevo.cpp \
  rpc/rpcquorums.cpp \
  script/sigcache.cpp \
  script/ismine.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  ui_interface.cpp \
  batchproof_container.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  sigma.cpp \
  lelantus.cpp \
  coin_containers.cpp \
  mtpstate.cpp \
  $(BITCOIN_CORE_H)

if ENABLE_ZMQ
libbitcoin_zmq_a_CPPFLAGS = $(BITCOIN_INCLUDES) $(ZMQ_CFLAGS) $(LIBBLSSIG_INCLUDES)
libbitcoin_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif


# wallet: shared between firod and firo-qt, but only linked
# when wallet enabled
libbitcoin_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(LIBBLSSIG_INCLUDES)
libbitcoin_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_wallet_a_SOURCES = \
  activemasternode.cpp \
  hdmint/hdmint.cpp \
  masternode-sync.cpp \
  hdmint/mintpool.cpp \
  hdmint/wallet.cpp \
  sigma.cpp \
  lelantus.cpp \
  wallet/crypter.cpp \
  wallet/bip39.cpp \
  wallet/mnemoniccontainer.cpp \
  wallet/db.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/sigmaspendbuilder.cpp \
  wallet/txbuilder.cpp \
  wallet/lelantusjoinsplitbuilder.cpp \
  wallet/walletexcept.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  wallet/authhelper.cpp \
  hdmint/tracker.cpp \
  policy/rbf.cpp \
  bip47/account.cpp \
  bip47/paymentchannel.cpp \
  bip47/bip47utils.cpp \
  bip47/paymentcode.cpp \
  bip47/secretpoint.cpp \
  primitives/mint_spend.cpp \
  $(BITCOIN_CORE_H)

# crypto primitives library
crypto_libbitcoin_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_CONFIG_INCLUDES)
crypto_libbitcoin_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libbitcoin_crypto_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/common.h \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h

crypto_libbitcoin_crypto_a_SOURCES += \
  crypto/progpow/include/ethash/ethash.h \
  crypto/progpow/include/ethash/ethash.hpp \
  crypto/progpow/include/ethash/hash_types.h \
  crypto/progpow/include/ethash/hash_types.hpp \
  crypto/progpow/include/ethash/keccak.h \
  crypto/progpow/include/ethash/keccak.hpp \
  crypto/progpow/include/ethash/progpow.hpp \
  crypto/progpow/include/ethash/version.h \
  crypto/progpow/lib/ethash/bit_manipulation.h \
  crypto/progpow/lib/ethash/builtins.h \
  crypto/progpow/lib/ethash/endianness.hpp \
  crypto/progpow/lib/ethash/ethash-internal.hpp \
  crypto/progpow/lib/ethash/ethash.cpp \
  crypto/progpow/lib/ethash/kiss99.hpp \
  crypto/progpow/lib/ethash/managed.cpp \
  crypto/progpow/lib/ethash/primes.c \
  crypto/progpow/lib/ethash/primes.h \
  crypto/progpow/lib/ethash/progpow.cpp \
  crypto/progpow/lib/keccak/keccak.c \
  crypto/progpow/lib/keccak/keccakf1600.c \
  crypto/progpow/lib/keccak/keccakf800.c \
  crypto/progpow/lib/support/attributes.h \
  crypto/progpow/helpers.hpp \
  crypto/progpow/firopow_test_vectors.hpp \
  crypto/progpow.h \
  crypto/progpow.cpp

# consensus: shared between all executables that validate any consensus rules.
libbitcoin_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(LIBBLSSIG_INCLUDES) $(PIC_FLAGS)
libbitcoin_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) $(PIC_FLAGS)
libbitcoin_consensus_a_SOURCES = \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  bls/bls.cpp \
  bls/bls.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  hash.cpp \
  flat-database.h \
  hash.h \
  prevector.h \
  crypto/scrypt.h \
  primitives/block.h \
  primitives/precomputed_hash.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/bitcoinconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  utilstrencodings.cpp \
  utilstrencodings.h \
  version.h \
  crypto/Lyra2Z/Lyra2.h \
  crypto/Lyra2Z/Lyra2.c \
  crypto/Lyra2Z/Lyra2Z.h \
  crypto/Lyra2Z/Lyra2Z.c \
  crypto/Lyra2Z/blake.c \
  crypto/Lyra2Z/sph_blake.h \
  crypto/Lyra2Z/sph_types.h \
  crypto/Lyra2Z/Sponge.c \
  crypto/Lyra2Z/Sponge.h \
  crypto/MerkleTreeProof/mtp.h \
  crypto/MerkleTreeProof/argon2.h \
  crypto/MerkleTreeProof/thread.h \
  crypto/MerkleTreeProof/merkle-tree.hpp \
  crypto/MerkleTreeProof/core.h \
  crypto/MerkleTreeProof/ref.h \
  crypto/MerkleTreeProof/blake2/blake2.h \
  crypto/MerkleTreeProof/blake2/blamka-round-opt.h \
  crypto/MerkleTreeProof/blake2/blake2-impl.h \
  crypto/MerkleTreeProof/blake2/blamka-round-ref.h \
  crypto/MerkleTreeProof/thread.c \
  crypto/MerkleTreeProof/core.c \
  crypto/MerkleTreeProof/ref.c \
  crypto/MerkleTreeProof/blake2/blake2b.c

# common: shared between firod, and firo-qt and non-server tools
libbitcoin_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(LIBBLSSIG_INCLUDES)
libbitcoin_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_common_a_SOURCES = \
  amount.cpp \
  base58.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  hdmint/hdmint.cpp \
  key.cpp \
  keystore.cpp \
  netaddress.cpp \
  netbase.cpp \
  protocol.cpp \
  saltedhasher.cpp \
  scheduler.cpp \
  script/sign.cpp \
  script/standard.cpp \
  warnings.cpp \
  $(BITCOIN_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libbitcoin_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(LIBBLSSIG_INCLUDES)
libbitcoin_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_util_a_SOURCES = \
  bls/bls_batchverifier.h \
  bls/bls_ies.cpp \
  bls/bls_ies.h \
  bls/bls_worker.cpp \
  bls/bls_worker.h \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  mbstring.cpp \
  fs.cpp \
  random.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  crypto/scrypt.cpp \
  primitives/block.cpp \
  bitcoin_bignum/allocators.h \
  bitcoin_bignum/bignum.h \
  bitcoin_bignum/compat.h \
  bitcoin_bignum/netbase.h \
  crypto/MerkleTreeProof/mtp.cpp \
  crypto/MerkleTreeProof/merkle-tree.cpp \
  $(BITCOIN_CORE_H)

liblelantus_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
liblelantus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
liblelantus_a_SOURCES = \
  liblelantus/challenge_generator.h \
  liblelantus/challenge_generator_impl.h \
  liblelantus/lelantus_primitives.h \
  liblelantus/lelantus_primitives.cpp \
  liblelantus/lelantus_proof.h \
  liblelantus/lelantus_prover.h \
  liblelantus/lelantus_prover.cpp \
  liblelantus/lelantus_verifier.h \
  liblelantus/lelantus_verifier.cpp \
  liblelantus/sigmaextended_proof.h \
  liblelantus/sigmaextended_prover.h \
  liblelantus/sigmaextended_prover.cpp \
  liblelantus/sigmaextended_verifier.h \
  liblelantus/sigmaextended_verifier.cpp \
  liblelantus/schnorr_proof.h \
  liblelantus/schnorr_prover.h \
  liblelantus/schnorr_prover.cpp \
  liblelantus/schnorr_verifier.h \
  liblelantus/schnorr_verifier.cpp \
  liblelantus/innerproduct_proof.h \
  liblelantus/innerproduct_proof_verifier.h \
  liblelantus/innerproduct_proof_verifier.cpp \
  liblelantus/innerproduct_proof_generator.h \
  liblelantus/innerproduct_proof_generator.cpp \
  liblelantus/range_proof.h \
  liblelantus/range_prover.h \
  liblelantus/range_prover.cpp \
  liblelantus/range_verifier.h \
  liblelantus/range_verifier.cpp \
  liblelantus/coin.h \
  liblelantus/coin.cpp \
  liblelantus/joinsplit.h \
  liblelantus/joinsplit.cpp \
  liblelantus/spend_metadata.h \
  liblelantus/spend_metadata.cpp \
  liblelantus/params.h \
  liblelantus/params.cpp

libsigma_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) -Werror
libsigma_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -Werror
libsigma_a_SOURCES = \
  sigma/r1_proof.h \
  sigma/r1_proof_generator.h \
  sigma/r1_proof_generator.hpp \
  sigma/r1_proof_verifier.h \
  sigma/r1_proof_verifier.hpp \
  sigma/sigmaplus_proof.h \
  sigma/sigmaplus_prover.h \
  sigma/sigmaplus_prover.hpp \
  sigma/sigmaplus_verifier.h \
  sigma/sigmaplus_verifier.hpp \
  sigma/sigma_primitives.h \
  sigma/sigma_primitives.hpp \
  sigma/coin.h \
  sigma/coin.cpp \
  sigma/coinspend.cpp \
  sigma/coinspend.h \
  sigma/spend_metadata.cpp \
  sigma/spend_metadata.h \
  sigma/params.h \
  sigma/params.cpp \
  sigma/openssl_context.h

if GLIBC_BACK_COMPAT
libbitcoin_util_a_SOURCES += compat/glibc_compat.cpp
AM_LDFLAGS += $(COMPAT_LDFLAGS)
endif

if ENABLE_CRASH_HOOKS
libbitcoin_util_a_SOURCES += stacktraces.cpp
libbitcoin_consensus_a_SOURCES += stacktraces.h
endif

# cli: shared between firo-cli and firo-qt
libbitcoin_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libbitcoin_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_cli_a_SOURCES = \
  rpc/client.cpp \
  $(BITCOIN_CORE_H)

nodist_libbitcoin_util_a_SOURCES = $(srcdir)/obj/build.h
#

# bitcoind binary #
firod_SOURCES = bitcoind.cpp
firod_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
firod_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
firod_LDFLAGS = $(LDFLAGS_WRAP_EXCEPTIONS) $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)
EXTRA_firod_DEPENDENCIES = $(LIBBLSSIG_LIBS)

if TARGET_WINDOWS
firod_SOURCES += bitcoind-res.rc
endif

firod_LDADD = \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_WALLET) \
  $(LIBFIRO_SIGMA) \
  $(LIBLELANTUS) \
  $(LIBBITCOIN_ZMQ) \
  $(LIBBITCOIN_CONSENSUS) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1) \
  $(LIBBLSSIG_LIBS)

firod_LDADD += $(BACKTRACE_LIB) $(TOR_LIBS) $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS) $(LIBBLSSIG_DEPENDS) -lz

# bitcoin-cli binary #
firo_cli_SOURCES = bitcoin-cli.cpp
firo_cli_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
firo_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
firo_cli_LDFLAGS = $(LDFLAGS_WRAP_EXCEPTIONS) $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
firo_cli_SOURCES += bitcoin-cli-res.rc
endif

firo_cli_LDADD = \
  $(LIBBITCOIN_CLI) \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_CRYPTO)

firo_cli_LDADD += $(BACKTRACE_LIB) $(BOOST_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# bitcoin-tx binary #
firo_tx_SOURCES = bitcoin-tx.cpp
firo_tx_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
firo_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
firo_tx_LDFLAGS = $(LDFLAGS_WRAP_EXCEPTIONS) $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
firo_tx_SOURCES += bitcoin-tx-res.rc
endif

firo_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBBITCOIN_COMMON) \
  $(LIBBITCOIN_UTIL) \
  $(LIBBITCOIN_CONSENSUS) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBSECP256K1)

firo_tx_LDADD += $(BACKTRACE_LIB) $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# bitcoinconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/bitcoinconsensus.h
libbitcoinconsensus_la_SOURCES = $(crypto_libbitcoin_crypto_a_SOURCES) $(libbitcoin_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libbitcoinconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libbitcoinconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS) $(LIBBLSSIG_LIBS) $(LIBBLSSIG_DEPENDS)
libbitcoinconsensus_la_LIBADD = $(LIBSECP256K1)
libbitcoinconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include $(LIBBLSSIG_INCLUDES) -DBUILD_BITCOIN_INTERNAL
libbitcoinconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
EXTRA_libbitcoinconsensus_la_DEPENDENCIES = $(LIBBLSSIG_LIBS)

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += tor.timestamp tor.timestamp.tmp

DISTCLEANFILES = obj/build.h

EXTRA_DIST = $(CTAES_DIST)


config/bitcoin-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/bitcoin-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/bitcoin-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/bitcoin-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-$(MAKE) -C tor clean
	-$(MAKE) -C bls-signatures clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__
	-rm -rf *.dSYM test/*.dSYM bench/*.dSYM qt/*.dSYM qt/test/*.dSYM

distclean-local:
	-rm -rf bls-signatures/build

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(PYTHON) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

osx_debug: $(bin_PROGRAMS)
	for i in $(bin_PROGRAMS); do mkdir -p $$i.dSYM/Contents/Resources/DWARF && $(DSYMUTIL_FLAT) -o $$i.dSYM/Contents/Resources/DWARF/$$(basename $$i) $$i &> /dev/null ; done

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(<D) $<

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_TESTS
include Makefile.test.include
else
check-local:
	$(error Please rerun configure with tests enabling flag)
endif

if ENABLE_ELYSIUM
include Makefile.elysium.include
endif
