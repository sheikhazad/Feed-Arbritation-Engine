/*
Handles:
  - Opening .pcap files with libpcap
  - Parsing Ethernet → IPv4 → UDP headers
  - Extracting:
      * UDP payload
      * CME sequence number
      * Metamako timestamp (from trailer)
  - Storing results in SideStatsInput
*/

// PcapProcessor.cpp

#include "PcapProcessor.hpp"

#include <cstring>
#include <iostream>

#if defined(_WIN32)
    // Platform-independent networking headers are abstracted via ntohs/ntohl,
    // but on Windows we still need winsock for those macros.
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/types.h>
#endif

#ifdef ENABLE_DEBUG_PRINTS
#include <DebugPerPacketEventLogger.hpp>
#include <PcapDumpWriter.hpp>
#endif

//Note: 
//A PCAP file is not one protocol.
//Network headers (Ethernet/IP/UDP) are big‑endian (Network Byte Order use Big Endian)on the wire 
//CME payload fields are little‑endian [because CME MDP 3.0 uses SBE (Simple Binary Encoding) which is little-endian]
//Metamako timestamp trailer is big‑endian (Metamako follows Network Byte Order)

/**
 * @brief Ethernet header (14 bytes on the wire).
 */
//Ensure that struct matches the exact binary layout of an Ethernet frame header.
#pragma pack(push, 1) //align all struct members on 1‑byte (no padding) boundaries in memory to match the incoming on-the-wire layout. 
//This is crucial for correct parsing of raw packet data.
struct EthernetHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype; //2 bytes
}; //__attribute__((packed)); not C++ standard, use #pragma pack instead

/**
 * @brief IPv4 header (minimum 20 bytes).
 */
struct IPv4Header {
    uint8_t version_ihl; // The IPv4 header packs two values into one byte: Version (4 bits) + IHL(Internet Header Length)(4 bits)
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

/**
 * @brief UDP header (8 bytes).
 */
struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop) //restore previous compiler's original alignment 

namespace {

// Standard IPv4 EtherType (0x0800).
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;

// Avoid conflict with macOS system macro IPPROTO_UDP.
constexpr uint8_t UDP_PROTOCOL_NUMBER = 17;

// Metamako trailer is always exactly 20 bytes at the end of the packet.
constexpr uint32_t METAMAKO_TRAILER_LEN = 20;

/**
 * @brief Read a big-endian 32-bit unsigned integer from a byte pointer.
 *
 * This function reads 4 bytes stored in big-endian order and assembles them
 * into a uint32_t value in the CPU's native integer representation.
 * Unlike ntohl(), which requires a uint32_t already loaded into memory,
 * read_be32() works directly from a raw byte pointer.
 *
 * @param p Pointer to 4 bytes in big-endian order.
 * @return Decoded uint32_t value (normal host-order integer).
 *
 * Example:
 *   Input bytes at p: 0x12 0x34 0x56 0x78 (big-endian)
 *   Returned value:   0x12345678
 *
 * Breakdown:
 *   (0x12 << 24) = 0x12 00 00 00
 *   (0x34 << 16) = 0x00 34 00 00
 *   (0x56 <<  8) = 0x00 00 56 00
 *   (0x78)       = 0x00 00 00 78
 *   --------------------------------
 *   OR them all = 0x12 34 56 78
 *
 * Note: The returned uint32_t has the same numeric value on all architectures;
 *       endianness affects only how bytes are stored in memory, not the integer
 *       value itself.
 */
inline uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |  //E.g. If p[0] = 0x12, shifting left 24 bits gives: 0x12 00 00 00
           (static_cast<uint32_t>(p[1]) << 16) |  //E.g. If p[1] = 0x34, shifting left 16 bits gives: 0x00 34 00 00
           (static_cast<uint32_t>(p[2]) << 8)  |  //E.g. If p[2] = 0x56, shifting left 8 bits gives: 0x00 00 56 00
            static_cast<uint32_t>(p[3]);          //E.g. If p[3] = 0x78, no shift gives: 0x00 00 00 78
}

} // namespace

// ============================================================
// 0. Construction
// ============================================================

/**
 * @brief 0. Default constructor — nothing special to initialize.
 */
PcapProcessor::PcapProcessor() = default;

// ============================================================
// 1. File processing
// ============================================================

/**
 * @brief 1. Process a single PCAP file using libpcap.
 *
 * Opens the file with libpcap and iterates over all packets. Each packet
 * is passed to processSinglePacket() for parsing, side classification, and
 * statistics recording.
 *
 * Debug behavior (when ENABLE_DEBUG_PRINTS is defined):
 *   - current_pcap_filename_ is set to the path.
 *   - file_start_logged_for_port_ is cleared.
 *   - For each port observed in this file, the first packet triggers a
 *     "=== Starting file: <pcap> ===" line in Debug_Side_<port>_raw.txt.
 *
 * @param path Path to the PCAP file.
 * @return true on success, false on failure.
 */
bool PcapProcessor::processFile(const std::string& path) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(path.c_str(), errbuf);

    if (!handle) {
        std::cerr << "Failed to open PCAP: " << path << " : " << errbuf << "\n";
        return false;
    }

    // Remember the current PCAP filename for debug logging.
    current_pcap_filename_ = path;


#ifdef ENABLE_DEBUG_PRINTS
    // For this file, no ports have yet had a "file start" line logged.
    file_start_logged_for_port_.clear();    
    PcapDumpWriter::setPcapFilename(current_pcap_filename_);
#endif

    const uint8_t* data = nullptr;
    pcap_pkthdr* header = nullptr;

    while (true) {
        //read packets one by one
        const int ret = pcap_next_ex(handle, &header, &data);

        if (ret == 1) {
            processSinglePacket(header, data);
        } else if (ret == -2) {
            // End of file.
            break;
        } else if (ret < 0) {
            std::cerr << "Error reading PCAP: " << pcap_geterr(handle) << "\n";
            break;
        }
    }

    pcap_close(handle);
    return true;
}

/**
 * @brief Return statistics for the requested side.
 */
const SideStatsInput& PcapProcessor::getSideStats(Side side) const {
    return (side == Side::A) ? side_a_ : side_b_;
}

// ============================================================
// 2. Packet dispatch
// ============================================================

/**
 * @brief 2. Process a single packet from the PCAP file.
 *
 * Dynamically detects which UDP destination ports correspond to Side A and Side B:
 *   - The first observed UDP destination port is assigned to Side A.
 *   - The first different UDP destination port is assigned to Side B.
 *   - Subsequent packets are classified based on these detected ports.
 *   - Any further distinct destination ports are ignored with a diagnostic message.
 *
 * Side naming convention is effectively Side_<portNumber> read from pcap>.
 *
 * Debug behavior (when ENABLE_DEBUG_PRINTS is defined):
 * 1. Entire packets are dumped to PcapDump_Side_<PortNumber>.txt in both
 *    raw and decoded form for analysis.
 * 2. Following info is stored in PerPacketEvent_Side_<PortNumber>.txt
 *   - For each port, the first packet in the current PCAP file triggers:
 *       "=== Starting file: <pcap file name> ==="
 *   - Every packet logs a minimal summary line.
 *   - Every trailer logs its timestamp fields.
 *
 * @param header libpcap packet header (contains caplen, timestamps, etc.).
 * @param data   Pointer to the start of the captured packet bytes.
 */
void PcapProcessor::processSinglePacket(const pcap_pkthdr* header,
                                    const uint8_t* data) {
    const uint8_t* udp_payload_start_ptr = nullptr;
    uint32_t udp_payload_len = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    if (!parseUdpPayload(data, header->caplen,
                           &udp_payload_start_ptr, &udp_payload_len,
                           &src_port, &dst_port)) {
        return;
    }

    // Use the UDP destination port as the feed-identifying port.
    const uint16_t feed_port = dst_port;

    #ifdef ENABLE_DEBUG_PRINTS
        //Dump entire packet to PcapDump_Side_<PortNumber>.txt in both raw and decoded form for analysis
        PcapDumpWriter::dumpPacket(feed_port, header, data);
    #endif


    // Determine which side this packet belongs to, based on observed destination ports.
    Side side;

    // If no ports have been detected yet, assign the first observed destination port to Side A.
    if (detected_port_a_ == 0 && detected_port_b_ == 0) {
        detected_port_a_ = feed_port;
        side = Side::A;
    }
    // If Side A is known but Side B is not, and this packet uses a different destination port,
    // assign that port to Side B.
    else if (detected_port_b_ == 0 &&
             feed_port != detected_port_a_) {
        detected_port_b_ = feed_port;
        side = Side::B;
    }
    // Otherwise, classify based on known destination ports.
    else if (feed_port == detected_port_a_) {
        side = Side::A;
    } else if (feed_port == detected_port_b_) {
        side = Side::B;
    } else {
        // A third distinct destination port has been observed. For robustness and clarity,
        // we ignore this packet and emit a diagnostic message indicating that port mapping
        // logic should be extended if more than two sides are required.
        std::cerr
            << "Warning: observed additional UDP destination port " << feed_port
            << " beyond the two mapped sides (Side_" << detected_port_a_
            << " and Side_" << detected_port_b_
            << "). Packet ignored. Extend port-to-side mapping logic if needed.\n";
        return;
    }

#ifdef ENABLE_DEBUG_PRINTS
    // For this PCAP file and this port, log a "file start" header once.
    if (!file_start_logged_for_port_[feed_port]) {
        DebugPerPacketEventLogger::log0_OnNewPcapFile(feed_port, current_pcap_filename_);
        file_start_logged_for_port_[feed_port] = true;
    }

    // Log a minimal per-packet summary (caplen + UDP payload length).
    DebugPerPacketEventLogger::log1_OnPacket(
        feed_port,
        static_cast<std::size_t>(header->caplen),
        static_cast<std::size_t>(udp_payload_len)
    );
#endif

    int64_t ts_ns{0};
    if (!decodeMetamakoTimestamp(side, data, header->caplen, ts_ns)) {
        return;
    }

#ifdef ENABLE_DEBUG_PRINTS
    // Derive seconds and nanoseconds from the nanosecond timestamp for trailer logging.
    const int64_t sec  = ts_ns / 1'000'000'000LL;
    const int64_t nsec = ts_ns % 1'000'000'000LL;

    DebugPerPacketEventLogger::log2_OnTrailer(
        feed_port,
        static_cast<uint32_t>(sec),
        static_cast<uint32_t>(nsec)
    );
#endif

    uint64_t seq{0};
    if (!decodeSequenceNumber(udp_payload_start_ptr, udp_payload_len, seq)) {
        return;
    }

    updateSideStatsForPacket(side, seq, ts_ns);
}

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
 *When reading a pcap file, we can see  CME Payload after skipping the 
 following headers (which are mandtory when packet is captured at the NIC lev el [on the wire]):
     - Ethernet header (14 bytes)
     - IPv4 header (usually 20 bytes)
     - UDP header (8 bytes) [in our case UDP, not TCP]

 * On success, returns a pointer to the UDP payload (excluding trailer),
 * its length, and the source/destination ports.
 */
bool PcapProcessor::parseUdpPayload(const uint8_t* data,
                                      uint32_t caplen,
                                      const uint8_t** udp_payload_start_ptr,
                                      uint32_t* udp_payload_len,
                                      uint16_t* src_port,
                                      uint16_t* dst_port) const {

    //1. Extract Ethernet header and verify EtherType is IPv4.
    if (caplen < sizeof(EthernetHeader))
        return false;

    const auto* eth = reinterpret_cast<const EthernetHeader*>(data);
    if (ntohs(eth->ethertype) != ETHERTYPE_IPV4)
        return false;

    //2. Extract IPv4 header and verify protocol is UDP.
    //[ Ethernet Header ][ IPv4 Header ][ UDP Header ][ Payload ]
    //Skip Ethernet Header to get to the start of the IPv4 Header.
    const uint8_t* ip_ptr = data + sizeof(EthernetHeader);
    if (caplen < sizeof(EthernetHeader) + sizeof(IPv4Header))
        return false;

    const auto* ip = reinterpret_cast<const IPv4Header*>(ip_ptr);
    //version_ihl = V + IHL (4 bits each) packed into one byte, e.g. 
    //0100 0101
    //^^^^ ----
    //V    IHL
    //We need to extract IHL to know the actual IP header length, which can be more than 20 bytes if there are options.
    const uint8_t ihl = static_cast<uint8_t>(ip->version_ihl & 0x0F); //Extract lorwer 4 bits for IHL

    //Convert IHL (in 32‑bit words) to actual bytes by multiplying by 4 (since each word is 4 bytes).
    //IHL is the number of 32-bit words in the IP header, so we multiply by 4 to get the length in bytes.
    const uint32_t ip_header_len = static_cast<uint32_t>(ihl) * 4U;

    //UDP_PROTOCOL_NUMBER = 17, which is the standard protocol number for UDP in the IPv4 header.
    //For TCP it would be 6, for example. We check this to ensure we're parsing the correct protocol.
    if (ip->protocol != UDP_PROTOCOL_NUMBER)
        return false;

    //3. Extract UDP header
    const uint8_t* udp_ptr = ip_ptr + ip_header_len;
    if (caplen < sizeof(EthernetHeader) + ip_header_len + sizeof(UdpHeader))
        return false;

    const auto* udp = reinterpret_cast<const UdpHeader*>(udp_ptr);

    *src_port = ntohs(udp->src_port);
    *dst_port = ntohs(udp->dst_port);

    //4. Calculate UDP payload start and length, accounting for the Metamako trailer at the end.
    //Byte offset/position where UDP payload begins
    //It tells how many bytes to skip before UDP data begins
    const uint32_t udp_payload_offset =
        static_cast<uint32_t>(sizeof(EthernetHeader)) +
        ip_header_len +
        static_cast<uint32_t>(sizeof(UdpHeader));

    if (caplen < udp_payload_offset + METAMAKO_TRAILER_LEN)
        return false;

    const uint32_t payload_with_trailer = caplen - udp_payload_offset;

    if (payload_with_trailer <= METAMAKO_TRAILER_LEN)
        return false;

    *udp_payload_len = payload_with_trailer - METAMAKO_TRAILER_LEN;
    //udp_payload_start_ptr points to the start(first byte) of UDP data (excluding trailer)
    *udp_payload_start_ptr = data + udp_payload_offset;

    return true;
}

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
 */
bool PcapProcessor::decodeMetamakoTimestamp(Side /*side*/,
                                               const uint8_t* packet_base,
                                               uint32_t caplen,
                                               int64_t& ts_ns) const {
    if (caplen < METAMAKO_TRAILER_LEN)
        return false;

    const uint8_t* trailer = packet_base + (caplen - METAMAKO_TRAILER_LEN);

    const uint32_t sec  = read_be32(trailer + 8);
    const uint32_t nsec = read_be32(trailer + 12);

    ts_ns = static_cast<int64_t>(sec) * 1'000'000'000LL +
            static_cast<int64_t>(nsec);
    return true;
}

// ============================================================
// 5. CME sequence extraction
// ============================================================

/**
 * @brief 5. Extract CME sequence number (first 4 bytes of UDP payload).
 *
 * CME MDP 3.0 uses little-endian encoding for the sequence number.
 */
bool PcapProcessor::decodeSequenceNumber(const uint8_t* udp_payload_start_ptr,
                                            uint32_t udp_payload_len,
                                            uint64_t& seq) const {
    if (udp_payload_len < 4U)
        return false;

    // Construct integer: Little-endian decoding of the first 4 bytes of UDP payload.
    seq = static_cast<uint64_t>(udp_payload_start_ptr[0]) |
          (static_cast<uint64_t>(udp_payload_start_ptr[1]) << 8) |
          (static_cast<uint64_t>(udp_payload_start_ptr[2]) << 16) |
          (static_cast<uint64_t>(udp_payload_start_ptr[3]) << 24);

    return true;
}

// ============================================================
// 6. Recording per-side stats
// ============================================================

/**
 * @brief 6. Update total packets received and store packet timestamp for the given side.
 *
 * If the sequence number already exists, keep the earliest timestamp.
 */
void PcapProcessor::updateSideStatsForPacket(Side side, uint64_t seq, int64_t ts_ns) {
    auto& stats = (side == Side::A) ? side_a_ : side_b_;
    stats.total_packets++;

    auto it = stats.seq_ts_um.find(seq);
    if (it == stats.seq_ts_um.end()) {
        stats.seq_ts_um.emplace(seq, ts_ns);
    } else if (ts_ns < it->second) {
        it->second = ts_ns;
    }
}


PcapProcessor::ParsedPacketForTest
PcapProcessor::parsePacketForTest(const uint8_t* data, uint32_t caplen)
{
    ParsedPacketForTest out;

    const uint8_t* udp_payload_start_ptr = nullptr;
    uint32_t udp_len = 0;
    uint16_t src = 0, dst = 0;

    if (!parseUdpPayload(data, caplen, &udp_payload_start_ptr, &udp_len, &src, &dst))
        return out;

    int64_t ts_ns = 0;
    if (!decodeMetamakoTimestamp(Side::A, data, caplen, ts_ns))
        return out;

    uint64_t seq = 0;
    if (!decodeSequenceNumber(udp_payload_start_ptr, udp_len, seq))
        return out;

    out.sequence = seq;
    out.timestamp_ns = ts_ns;
    out.src_port = src;
    out.dst_port = dst;
    out.ok = true;
    return out;
}

