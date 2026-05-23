#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

#include <pcap/pcap.h>
#include "Types.hpp"

/**
 * @brief Processor for PCAP files containing CME MDP 3.0 UDP traffic
 *        with Metamako trailers.
 *
 * Functions are ordered in the same order as the packet processing pipeline:
 *
 *   0. Construction
 *   1. File processing
 *   2. Packet dispatch
 *   3. UDP payload extraction
 *   4. Metamako trailer timestamp extraction
 *   5. CME sequence extraction
 *   6. Recording per-side stats
 */
class PcapProcessor {
public:
    // ============================================================
    // 0. Construction
    // ============================================================

    /**
     * @brief 0. Default constructor.
     */
    PcapProcessor();

    // ============================================================
    // 1. File processing
    // ============================================================

    /**
     * @brief 1. Process a single PCAP file using libpcap.
     *
     * Opens the file with libpcap and iterates over all packets, passing
     * each one to processSinglePacket() for parsing and classification.
     *
     * @param path Path to the PCAP file.
     * @return true on success, false on failure.
     */
    bool processFile(const std::string& path);

    /**
     * @brief Return statistics for the requested side.
     *
     * @param side Side::A or Side::B.
     * @return Reference to the corresponding SideStatsInput.
     */
    const SideStatsInput& getSideStats(Side side) const;

    /**
     * @brief Get dynamically detected UDP port for Side A.
     *
     * Returns 0 if no packets for Side A were seen.
     */
    uint16_t getDetectedPortA() const { return detected_port_a_; }

    /**
     * @brief Get dynamically detected UDP port for Side B.
     *
     * Returns 0 if no packets for Side B were seen.
     */
    uint16_t getDetectedPortB() const { return detected_port_b_; }

private:
    // ============================================================
    // 2. Packet dispatch
    // ============================================================

    /**
     * @brief 2. Process a single packet from the PCAP file.
     *
     * Steps:
     *   1. Extract UDP payload.
     *   2. Determine side (A or B) based on dynamically observed destination ports.
     *   3. Extract Metamako timestamp.
     *   4. Extract CME sequence number.
     *   5. Record packet in per-side statistics.
     *
     * Side naming is effectively Side_<portNumber>, where the port number
     * is the UDP destination port read from the PCAP. The first distinct
     * destination port is mapped to Side A, the second distinct destination
     * port is mapped to Side B. Any further distinct ports are ignored with
     * a diagnostic message.
     *
     * @param header libpcap packet header (contains caplen, timestamps, etc.).
     * @param data   Pointer to the start of the captured packet bytes.
     */
    void processSinglePacket(const pcap_pkthdr* header, const uint8_t* data);

    // ============================================================
    // 3. UDP payload extraction
    // ============================================================

    /**
     * @brief 3. Parse Ethernet → IPv4 → UDP and return pointer to UDP payload.
     *
     * Validates that:
     *   - The packet is long enough for Ethernet + IPv4 + UDP.
     *   - The EtherType is IPv4.
     *   - The protocol is UDP.
     *   - There is enough space for the Metamako trailer at the end.
     *
     * On success, returns a pointer to the UDP payload (excluding trailer),
     * its length, and the source/destination ports.
     *
     * @param data            Pointer to the start of the captured packet.
     * @param caplen          Captured length of the packet.
     * @param udp_payload     Output: pointer to the UDP payload (excluding trailer).
     * @param udp_payload_len Output: length of the UDP payload (excluding trailer).
     * @param src_port        Output: UDP source port (host byte order).
     * @param dst_port        Output: UDP destination port (host byte order).
     * @return true on success, false if the packet is not a valid UDP/IPv4 packet
     *         with a Metamako trailer.
     */
    bool parseUdpPayload(const uint8_t* data,
                           uint32_t caplen,
                           const uint8_t** udp_payload,
                           uint32_t* udp_payload_len,
                           uint16_t* src_port,
                           uint16_t* dst_port) const;

    // ============================================================
    // 4. Metamako trailer timestamp extraction
    // ============================================================

    /**
     * @brief 4. Extract Metamako timestamp from the last 20 bytes of the packet.
     *
     * Trailer layout (20 bytes total):
     *   offset 8  → seconds (big-endian uint32)
     *   offset 12 → nanoseconds (big-endian uint32)
     *
     * The function returns the timestamp as nanoseconds since epoch.
     *
     * @param side        Side (A or B) for logical classification (not used for debug).
     * @param packet_base Pointer to the start of the packet.
     * @param caplen      Captured length of the packet.
     * @param ts_ns       Output: timestamp in nanoseconds since epoch.
     * @return true on success, false if trailer is missing or malformed.
     */
    bool decodeMetamakoTimestamp(Side side,
                                    const uint8_t* packet_base,
                                    uint32_t caplen,
                                    int64_t& ts_ns) const;

    // ============================================================
    // 5. CME sequence extraction
    // ============================================================

    /**
     * @brief 5. Extract CME sequence number (first 4 bytes of UDP payload).
     *
     * CME MDP 3.0 uses little-endian encoding for the sequence number.
     *
     * @param udp_payload     Pointer to the UDP payload.
     * @param udp_payload_len Length of the UDP payload in bytes.
     * @param seq             Output: decoded sequence number.
     * @return true on success, false if payload is too short.
     */
    bool decodeSequenceNumber(const uint8_t* udp_payload,
                                 uint32_t udp_payload_len,
                                 uint64_t& seq) const;

    // ============================================================
    // 6. Recording per-side stats
    // ============================================================

    /**
     * @brief 6. Store packet timestamp for the given side.
     *
     * If the sequence number already exists, the earliest timestamp is kept.
     *
     * @param side  Side::A or Side::B.
     * @param seq   CME sequence number.
     * @param ts_ns Timestamp in nanoseconds since epoch.
     */
    void updateSideStatsForPacket(Side side, uint64_t seq, int64_t ts_ns);

    /**
     * @brief Dynamically detected UDP port for Side A.
     *
     * Set when the first Side A packet is classified. 0 means "not yet detected".
     */
    uint16_t detected_port_a_ = 0;

    /**
     * @brief Dynamically detected UDP port for Side B.
     *
     * Set when the first Side B packet is classified. 0 means "not yet detected".
     */
    uint16_t detected_port_b_ = 0;

    /**
     * @brief Name of the PCAP file currently being processed.
     *
     * Used only for debug logging (DebugPerPacketEventLogger) to annotate
     * per-port raw debug files with "=== Starting file: <pcap> ===" markers.
     */
    std::string current_pcap_filename_;

#ifdef ENABLE_DEBUG_PRINTS
    /**
     * @brief Tracks, for the current PCAP file, which ports have already had
     *        a "file start" debug line emitted.
     *
     * Cleared at the start of each processFile() call.
     */
    std::unordered_map<uint16_t, bool> file_start_logged_for_port_;
#endif

    SideStatsInput side_a_;
    SideStatsInput side_b_;

    public:
    struct ParsedPacketForTest {
        uint64_t sequence = 0;
        int64_t timestamp_ns = 0;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        bool ok = false;
    };
    
    ParsedPacketForTest parsePacketForTest(const uint8_t* data, uint32_t caplen);
    
};
