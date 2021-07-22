#include "elysium/log.h"

#include "chainparamsbase.h"
#include "util.h"
#include "utiltime.h"

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/once.hpp>

#include <assert.h>
#include <stdio.h>
#include <atomic>
#include <string>
#include <vector>

// Default log files
const std::string LOG_FILENAME    = "elysium.log";

// Options
static const long LOG_BUFFERSIZE  =  8000000; //  8 MB
static const long LOG_SHRINKSIZE  = 50000000; // 50 MB

// Debug flags
bool elysium_debug_parser_data        = true;
bool elysium_debug_parser_readonly    = 0;
//! Print information to potential DEx payments and outputs
bool elysium_debug_parser             = 0;
bool elysium_debug_verbose            = 0;
bool elysium_debug_verbose2           = 0;
bool elysium_debug_verbose3           = 0;
bool elysium_debug_vin                = 0;
bool elysium_debug_script             = 0;
bool elysium_debug_send               = 1;
bool elysium_debug_tokens             = 0;
//! Print information about payloads with non-sequential sequence number
bool elysium_debug_spec               = 0;
bool elysium_debug_ely                = 0;
bool elysium_debug_tally              = 1;
bool elysium_debug_sp                 = 1;
bool elysium_debug_sto                = 1;
bool elysium_debug_txdb               = 0;
bool elysium_debug_persistence        = 0;
bool elysium_debug_ui                 = 0;
bool elysium_debug_pending            = 1;
//! Print transaction fields, when interpreting packets
bool elysium_debug_packets            = 1;
//! Print transaction fields, when interpreting packets (in RPC mode)
bool elysium_debug_packets_readonly   = 0;
bool elysium_debug_walletcache        = 0;
//! Print each line added to consensus hash
bool elysium_debug_consensus_hash     = 0;
//! Print consensus hashes for each block when parsing
bool elysium_debug_consensus_hash_every_block = 0;
//! Print extra info on alert processing
bool elysium_debug_alerts             = 1;
//! Print consensus hashes for each transaction when parsing
bool elysium_debug_consensus_hash_every_transaction = 0;
//! Debug fees
bool elysium_debug_fees               = 1;

/**
 * LogPrintf() has been broken a couple of times now
 * by well-meaning people adding mutexes in the most straightforward way.
 * It breaks because it may be called by global destructors during shutdown.
 * Since the order of destruction of static/global objects is undefined,
 * defining a mutex as a global object doesn't work (the mutex gets
 * destroyed, and then some later destructor calls OutputDebugStringF,
 * maybe indirectly, and you get a core dump at shutdown trying to lock
 * the mutex).
 */
static boost::once_flag debugLogInitFlag = BOOST_ONCE_INIT;
/**
 * We use boost::call_once() to make sure these are initialized
 * in a thread-safe manner the first time called:
 */
static FILE* fileout = NULL;
static boost::mutex* mutexDebugLog = NULL;
/** Flag to indicate, whether the Elysium log file should be reopened. */
extern std::atomic<bool> fReopenElysiumLog;

/**
 * @return The current timestamp in the format: 2009-01-03 18:15:05
 */
static std::string GetTimestamp()
{
    return DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime());
}

/**
 * Prints to the standard output, usually the console.
 *
 * The configuration option "-logtimestamps" can be used to indicate, whether
 * the message should be prepended with a timestamp.
 *
 * @param str[in]  The message to print
 * @return The total number of characters written
 */
static int ConsolePrint(const std::string& str)
{
    int ret = 0; // Number of characters written
    static bool fStartedNewLine = true;

    if (fLogTimestamps && fStartedNewLine) {
        ret = fprintf(stdout, "%s %s", GetTimestamp().c_str(), str.c_str());
    } else {
        ret = fwrite(str.data(), 1, str.size(), stdout);
    }
    if (!str.empty() && str[str.size()-1] == '\n') {
        fStartedNewLine = true;
    } else {
        fStartedNewLine = false;
    }
    fflush(stdout);

    return ret;
}

/**
 * Returns path for debug log file.
 *
 * The log file can be specified via startup option "--elysiumlogfile=/path/to/exodus.log",
 * and if none is provided, then the client's datadir is used as default location.
 */
static boost::filesystem::path GetLogPath()
{
    boost::filesystem::path pathLogFile;
    std::string strLogPath = GetArg("-elysiumlogfile", "");

    if (!strLogPath.empty()) {
        pathLogFile = boost::filesystem::path(strLogPath);
        TryCreateDirectory(pathLogFile.parent_path());
    } else {
        pathLogFile = GetDataDir() / LOG_FILENAME;
    }

    return pathLogFile;
}

/**
 * Opens debug log file.
 */
static void DebugLogInit()
{
    assert(fileout == NULL);
    assert(mutexDebugLog == NULL);

    boost::filesystem::path pathDebug = GetLogPath();
    fileout = fopen(pathDebug.string().c_str(), "a");

    if (fileout) {
        setbuf(fileout, NULL); // Unbuffered
    } else {
        ConsolePrint(tfm::format("Failed to open debug log file: %s\n", pathDebug.string()));
    }

    mutexDebugLog = new boost::mutex();
}

/**
 * Prints to log file.
 *
 * The configuration options "-logtimestamps" can be used to indicate, whether
 * the message to log should be prepended with a timestamp.
 *
 * If "-printtoconsole" is enabled, then the message is written to the standard
 * output, usually the console, instead of a log file.
 *
 * @param str[in]  The message to log
 * @return The total number of characters written
 */
int LogFilePrint(const std::string& str)
{
    int ret = 0; // Number of characters written
    if (fPrintToConsole) {
        // Print to console
        ret = ConsolePrint(str);
    }
    else if (fPrintToDebugLog && AreBaseParamsConfigured()) {
        static bool fStartedNewLine = true;
        boost::call_once(&DebugLogInit, debugLogInitFlag);

        if (fileout == NULL) {
            return ret;
        }
        boost::mutex::scoped_lock scoped_lock(*mutexDebugLog);

        // Reopen the log file, if requested
        if (fReopenElysiumLog) {
        	fReopenElysiumLog = false;
            boost::filesystem::path pathDebug = GetLogPath();
            if (freopen(pathDebug.string().c_str(), "a", fileout) != NULL) {
                setbuf(fileout, NULL); // Unbuffered
            }
        }

        // Printing log timestamps can be useful for profiling
        if (fLogTimestamps && fStartedNewLine) {
            ret += fprintf(fileout, "%s ", GetTimestamp().c_str());
        }
        if (!str.empty() && str[str.size()-1] == '\n') {
            fStartedNewLine = true;
        } else {
            fStartedNewLine = false;
        }
        ret += fwrite(str.data(), 1, str.size(), fileout);
    }

    return ret;
}

/**
 * Determine whether to override compiled debug levels via enumerating startup option --elysiumdebug.
 *
 * Example usage (granular categories)    : --elysiumdebug=parser --elysiumdebug=ui
 * Example usage (enable all categories)  : --elysiumdebug=all
 * Example usage (disable all debugging)  : --elysiumdebug=none
 * Example usage (disable all except XYZ) : --elysiumdebug=none --omnidebug=parser --elysiumdebug=sto
 */
void InitDebugLogLevels()
{
    if (!IsArgSet("-elysiumdebug")) {
        return;
    }

    const std::vector<std::string>& debugLevels = mapMultiArgs.at("-elysiumdebug");

    for (std::vector<std::string>::const_iterator it = debugLevels.begin(); it != debugLevels.end(); ++it) {
        if (*it == "parser_data") elysium_debug_parser_data = true;
        if (*it == "parser_readonly") elysium_debug_parser_readonly = true;
        if (*it == "parser") elysium_debug_parser = true;
        if (*it == "verbose") elysium_debug_verbose = true;
        if (*it == "verbose2") elysium_debug_verbose2 = true;
        if (*it == "verbose3") elysium_debug_verbose3 = true;
        if (*it == "vin") elysium_debug_vin = true;
        if (*it == "script") elysium_debug_script = true;
        if (*it == "send") elysium_debug_send = true;
        if (*it == "tokens") elysium_debug_tokens = true;
        if (*it == "spec") elysium_debug_spec = true;
        if (*it == "ely") elysium_debug_ely = true;
        if (*it == "tally") elysium_debug_tally = true;
        if (*it == "sp") elysium_debug_sp = true;
        if (*it == "sto") elysium_debug_sto = true;
        if (*it == "txdb") elysium_debug_txdb = true;
        if (*it == "persistence") elysium_debug_persistence = true;
        if (*it == "ui") elysium_debug_ui = true;
        if (*it == "pending") elysium_debug_pending = true;
        if (*it == "packets") elysium_debug_packets = true;
        if (*it == "packets_readonly") elysium_debug_packets_readonly = true;
        if (*it == "walletcache") elysium_debug_walletcache = true;
        if (*it == "consensus_hash") elysium_debug_consensus_hash = true;
        if (*it == "consensus_hash_every_block") elysium_debug_consensus_hash_every_block = true;
        if (*it == "alerts") elysium_debug_alerts = true;
        if (*it == "consensus_hash_every_transaction") elysium_debug_consensus_hash_every_transaction = true;
        if (*it == "fees") elysium_debug_fees = true;
        if (*it == "none" || *it == "all") {
            bool allDebugState = false;
            if (*it == "all") allDebugState = true;
            elysium_debug_parser_data = allDebugState;
            elysium_debug_parser_readonly = allDebugState;
            elysium_debug_parser = allDebugState;
            elysium_debug_verbose = allDebugState;
            elysium_debug_verbose2 = allDebugState;
            elysium_debug_verbose3 = allDebugState;
            elysium_debug_vin = allDebugState;
            elysium_debug_script = allDebugState;
            elysium_debug_send = allDebugState;
            elysium_debug_tokens = allDebugState;
            elysium_debug_spec = allDebugState;
            elysium_debug_ely = allDebugState;
            elysium_debug_tally = allDebugState;
            elysium_debug_sp = allDebugState;
            elysium_debug_sto = allDebugState;
            elysium_debug_txdb = allDebugState;
            elysium_debug_persistence = allDebugState;
            elysium_debug_ui = allDebugState;
            elysium_debug_pending = allDebugState;
            elysium_debug_packets =  allDebugState;
            elysium_debug_packets_readonly =  allDebugState;
            elysium_debug_walletcache = allDebugState;
            elysium_debug_consensus_hash = allDebugState;
            elysium_debug_consensus_hash_every_block = allDebugState;
            elysium_debug_alerts = allDebugState;
            elysium_debug_consensus_hash_every_transaction = allDebugState;
            elysium_debug_fees = allDebugState;
        }
    }
}

/**
 * Scrolls debug log, if it's getting too big.
 */
void ShrinkDebugLog()
{
    boost::filesystem::path pathLog = GetLogPath();
    FILE* file = fopen(pathLog.string().c_str(), "r");

    if (file && boost::filesystem::file_size(pathLog) > LOG_SHRINKSIZE) {
        // Restart the file with some of the end
        char* pch = new char[LOG_BUFFERSIZE];
        if (NULL != pch) {
            fseek(file, -LOG_BUFFERSIZE, SEEK_END);
            int nBytes = fread(pch, 1, LOG_BUFFERSIZE, file);
            fclose(file);
            file = NULL;

            file = fopen(pathLog.string().c_str(), "w");
            if (file) {
                fwrite(pch, 1, nBytes, file);
                fclose(file);
                file = NULL;
            }
            delete[] pch;
        }
    } else if (NULL != file) {
        fclose(file);
        file = NULL;
    }
}
