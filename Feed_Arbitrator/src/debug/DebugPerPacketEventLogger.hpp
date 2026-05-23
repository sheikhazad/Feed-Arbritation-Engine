#pragma once

#include <cstdint>
#include <cstddef>
#include <string>


//-------------------------------------------------------------------------------------------------------------------//
/**************************This file can be ignored. Its purpose is just debugging and analysis.**********************/
//-------------------------------------------------------------------------------------------------------------------//


/**
 * @brief Per-packet debug event logger.
 *
 * This class receives per-packet and per-trailer debug events and writes
 * minimal, human-readable summaries into per-port raw debug files:
 *
 *  PerPacketEvent_Side_<Port>.txt
 *
 * Responsibilities:
 *   - Lazily open per-port debug files on first use.
 *   - Log packet summaries (caplen, UDP payload length).
 *   - Log trailer timestamps (seconds, nanoseconds).
 *   - Log PCAP file boundaries when a new file starts.
 *
 * This logger is intentionally lightweight and does not perform any deep
 * packet inspection or diffing. It is designed to be safe to use on large
 * PCAPs without generating excessive output.
 */
class DebugPerPacketEventLogger {
public:
    /**
     * @brief Notify the logger that a new PCAP file is starting for a given port.
     *
     * This writes a header line of the form:
     *   === Starting file: <pcapFilePath> ===
     *
     * The per-port debug file is opened lazily if it does not already exist.
     *
     * @param port         UDP port number associated with this side.
     * @param pcapFilePath Full path or name of the PCAP file being processed.
     */
    static void log0_OnNewPcapFile(uint16_t port,
                                   const std::string& pcapFilePath);

    /**
     * @brief Log a per-packet summary for a given port.
     *
     * This writes a single line of the form:
     *   Packet: caplen=<caplen> udp_payload_len=<udpPayloadLen>
     *
     * @param port          UDP port number associated with this side.
     * @param caplen        Captured length of the packet (PCAP caplen).
     * @param udpPayloadLen Length of the UDP payload (excluding trailer).
     */
    static void log1_OnPacket(uint16_t port,
                              std::size_t caplen,
                              std::size_t udpPayloadLen);

    /**
     * @brief Log a Metamako trailer timestamp for a given port.
     *
     * This writes a single line of the form:
     *   Trailer: sec=<sec> nsec=<nsec>
     *
     * @param port UDP port number associated with this side.
     * @param sec  Seconds field from the Metamako trailer.
     * @param nsec Nanoseconds field from the Metamako trailer.
     */
    static void log2_OnTrailer(uint16_t port,
                               uint32_t sec,
                               uint32_t nsec);

    /**
     * @brief Flush all open debug files.
     *
     * This ensures that all buffered output is written to disk. It does not
     * close the files; they remain open for subsequent logging.
     */
    static void flushAllOpenFiles();

private:
    // Internal helper to obtain (and lazily initialize) the per-port file.
    static std::ostream& getOrCreateStreamForPort(uint16_t port);
};
