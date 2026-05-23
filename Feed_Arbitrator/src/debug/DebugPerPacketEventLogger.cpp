#include <DebugPerPacketEventLogger.hpp>

#include <fstream>
#include <unordered_map>
#include <string>
#include <utility>


//-------------------------------------------------------------------------------------------------------------------//
/**************************This file can be ignored. Its purpose is just debugging and analysis.**********************/
//-------------------------------------------------------------------------------------------------------------------//

/**
 * @brief Internal structure holding per-port logging state.
 *
 * Each port has its own output file stream and a flag indicating whether
 * the "starting file" header has been written for the current PCAP file.
 */
namespace {
    struct PerPortState {
        std::ofstream file;
        bool hasAnyOutput = false;
    };

    // Map: port → per-port logging state.
    std::unordered_map<uint16_t, PerPortState> g_portStates;

    /**
     * @brief Build the filename for a given port.
     *
     * The format is:
     *   PerPacketEvent_Side_<port>.txt
     */
    std::string makeFilenameForPort(uint16_t port) {
        return "PerPacketEvent_Side_" + std::to_string(port) + ".txt";
    }
}

/**
 * @brief Internal helper to obtain (and lazily initialize) the per-port file.
 *
 * If the file for the given port is not yet open, it is opened in append mode.
 * Subsequent calls reuse the same stream.
 */
std::ostream& DebugPerPacketEventLogger::getOrCreateStreamForPort(uint16_t port) {
    PerPortState& state = g_portStates[port];

    if (!state.file.is_open()) {
        const std::string filename = makeFilenameForPort(port);
        state.file.open(filename, std::ios::out | std::ios::app);
    }

    return state.file;
}

/**
 * @brief 0. Notify the logger that a new PCAP file is starting for a given port.
 */
void DebugPerPacketEventLogger::log0_OnNewPcapFile(uint16_t port,
                                                   const std::string& pcapFilePath) {
    std::ostream& os = getOrCreateStreamForPort(port);

    os << "=== Starting file: " << pcapFilePath << " ===\n";
    g_portStates[port].hasAnyOutput = true;
}

/**
 * @brief 1. Log a per-packet summary for a given port.
 */
void DebugPerPacketEventLogger::log1_OnPacket(uint16_t port,
                                              std::size_t caplen,
                                              std::size_t udpPayloadLen) {
    std::ostream& os = getOrCreateStreamForPort(port);

    os << "Packet: caplen=" << caplen
       << " udp_payload_len=" << udpPayloadLen << "\n";

    g_portStates[port].hasAnyOutput = true;
}

/**
 * @brief 2. Log a Metamako trailer timestamp for a given port.
 */
void DebugPerPacketEventLogger::log2_OnTrailer(uint16_t port,
                                               uint32_t sec,
                                               uint32_t nsec) {
    std::ostream& os = getOrCreateStreamForPort(port);

    os << "Trailer: sec=" << sec
       << " nsec=" << nsec << "\n";

    g_portStates[port].hasAnyOutput = true;
}

/**
 * @brief 9. Flush all open debug files.
 */
void DebugPerPacketEventLogger::flushAllOpenFiles() {
    for (auto& kv : g_portStates) {
        PerPortState& state = kv.second;
        if (state.file.is_open()) {
            state.file.flush();
        }
    }
}
