#ifndef ELYSIUM_LOG_H
#define ELYSIUM_LOG_H

#include "util.h"
#include "tinyformat.h"

#include <string>

/** Prints to the log file. */
int LogFilePrint(const std::string& str);

/** Determine whether to override compiled debug levels. */
void InitDebugLogLevels();

/** Scrolls log file, if it's getting too big. */
void ShrinkDebugLog();

// Debug flags
extern bool elysium_debug_parser_data;
extern bool elysium_debug_parser_readonly;
extern bool elysium_debug_parser;
extern bool elysium_debug_verbose;
extern bool elysium_debug_verbose2;
extern bool elysium_debug_verbose3;
extern bool elysium_debug_vin;
extern bool elysium_debug_script;
extern bool elysium_debug_send;
extern bool elysium_debug_tokens;
extern bool elysium_debug_spec;
extern bool elysium_debug_ely;
extern bool elysium_debug_tally;
extern bool elysium_debug_sp;
extern bool elysium_debug_sto;
extern bool elysium_debug_txdb;
extern bool elysium_debug_persistence;
extern bool elysium_debug_ui;
extern bool elysium_debug_pending;
extern bool elysium_debug_packets;
extern bool elysium_debug_packets_readonly;
extern bool elysium_debug_walletcache;
extern bool elysium_debug_consensus_hash;
extern bool elysium_debug_consensus_hash_every_block;
extern bool elysium_debug_alerts;
extern bool elysium_debug_consensus_hash_every_transaction;
extern bool elysium_debug_fees;

/* When we switch to C++11, this can be switched to variadic templates instead
 * of this macro-based construction (see tinyformat.h).
 */
#define MAKE_ELYSIUM_ERROR_AND_LOG_FUNC(n)                                    \
    template<TINYFORMAT_ARGTYPES(n)>                                            \
    static inline int PrintToLog(const char* format, TINYFORMAT_VARARGS(n))     \
    {                                                                           \
        return LogFilePrint(tfm::format(format, TINYFORMAT_PASSARGS(n)));       \
    }                                                                           \
    template<TINYFORMAT_ARGTYPES(n)>                                            \
    static inline int PrintToLog(TINYFORMAT_VARARGS(n))                         \
    {                                                                           \
        return LogFilePrint(tfm::format("%s", TINYFORMAT_PASSARGS(n)));         \
    }

TINYFORMAT_FOREACH_ARGNUM(MAKE_ELYSIUM_ERROR_AND_LOG_FUNC)

#undef MAKE_ELYSIUM_ERROR_AND_LOG_FUNC


#endif // ELYSIUM_LOG_H
