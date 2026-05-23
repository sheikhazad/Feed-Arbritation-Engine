#include "PcapDumpWriter.hpp"
#include "PcapWirePrinter.hpp"

#include <pcap/pcap.h>

#include <fstream>
#include <unordered_map>

#if defined(_WIN32)
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

//-------------------------------------------------------------------------------------------------------------------//
/**************************This file can be ignored. Its purpose is just debugging and analysis.**********************/
//-------------------------------------------------------------------------------------------------------------------//

namespace {

// PCAP filename printed at top of each dump file.
std::string g_pcap_filename;

// Max packets to dump per port (0 = unlimited).
std::size_t g_max_packets_to_dump = 1;

// Per-port counters.
std::unordered_map<uint16_t, std::size_t> g_packets_dumped;

// Per-port output streams (lazy-opened).
std::unordered_map<uint16_t, std::ofstream> g_streams;

/**
 * @brief Get or create output stream for a port.
 *
 * Writes the PCAP filename header on first open.
 */
std::ostream& getStream(uint16_t port) {
    auto it = g_streams.find(port);
    if (it == g_streams.end()) {
        const std::string fname = "PcapDump_Side_" + std::to_string(port) + ".txt";
        std::ofstream ofs(fname, std::ios::out | std::ios::trunc);

        if (!g_pcap_filename.empty()) {
            ofs << "=== PCAP File: " << g_pcap_filename << " ===\n\n";
        }

        g_streams.emplace(port, std::move(ofs));
        it = g_streams.find(port);
    }
    return it->second;
}

} // namespace

// ======================================================================
// Public API
// ======================================================================

void PcapDumpWriter::setPcapFilename(const std::string& filename) {
    g_pcap_filename = filename;
}

void PcapDumpWriter::setMaxPacketsToDump(std::size_t n) {
    g_max_packets_to_dump = n;
}

void PcapDumpWriter::dumpPacket(uint16_t port,
                                const pcap_pkthdr* header,
                                const uint8_t* data) {
    if (!header || !data) {
        return;
    }

    auto& count = g_packets_dumped[port];
    if (g_max_packets_to_dump != 0 && count >= g_max_packets_to_dump) {
        return;
    }

    ++count;

    std::ostream& os = getStream(port);

    const std::size_t caplen = header->caplen;

    os << "=== Packet #" << count
       << " (caplen = " << caplen << " bytes) ===\n";

    // Ethernet header
    if (caplen < 14) {
        os << "[Truncated Ethernet header]\n\n";
        return;
    }

    os << "------------ Ethernet Header (raw) ------------\n";
    PcapWirePrinter::printHexAscii(os, data, 14);

    os << "------ Ethernet Header (decoded) ------\n";
    PcapWirePrinter::printEthernetHeader(os, data);
    os << "\n";

    // IPv4 header
    const uint8_t* ip = data + 14;
    if (caplen < 14 + 20) {
        os << "[Truncated IPv4 header]\n\n";
        return;
    }

    const uint8_t ihl = ip[0] & 0x0F;
    const std::size_t ip_len = static_cast<std::size_t>(ihl) * 4U;

    if (caplen < 14 + ip_len) {
        os << "[IPv4 header length exceeds captured bytes]\n\n";
        return;
    }

    os << "------------ IPv4 Header (raw) ------------\n";
    PcapWirePrinter::printHexAscii(os, ip, ip_len);

    os << "------ IPv4 Header (decoded) ------\n";
    PcapWirePrinter::printIPv4Header(os, ip, ip_len);
    os << "\n";

    // UDP header
    const uint8_t* udp = ip + ip_len;
    if (caplen < 14 + ip_len + 8) {
        os << "[Truncated UDP header]\n\n";
        return;
    }

    os << "------------ UDP Header (raw) ------------\n";
    PcapWirePrinter::printHexAscii(os, udp, 8);

    os << "------ UDP Header (decoded) ------\n";
    PcapWirePrinter::printUDPHeader(os, udp);
    os << "\n";

    // Payload + trailer
    const uint8_t* payload = udp + 8;
    const std::size_t remaining = caplen - (14 + ip_len + 8);

    constexpr std::size_t TRAILER_LEN = 20;

    const std::size_t payload_len =
        (remaining > TRAILER_LEN) ? (remaining - TRAILER_LEN) : remaining;

    const std::size_t trailer_len =
        (remaining > TRAILER_LEN) ? TRAILER_LEN : 0;

    // Payload (hex + ASCII)
    os << "------------ UDP Payload (hex + ASCII) ------------\n";
    if (payload_len > 0) {
        PcapWirePrinter::printHexAscii(os, payload, payload_len);
    } else {
        os << "[No payload]\n";
    }
    os << "\n";

    // Payload (ASCII only)
    os << "------------ UDP Payload (ASCII only) ------------\n";
    if (payload_len > 0) {
        PcapWirePrinter::printAsciiOnly(os, payload, payload_len);
    } else {
        os << "[No payload]\n";
    }
    os << "\n";

    // Trailer (raw)
    const uint8_t* trailer = payload + payload_len;

    os << "------------ Trailer (raw) ------------\n";
    if (trailer_len > 0) {
        PcapWirePrinter::printHexAscii(os, trailer, trailer_len);
    } else {
        os << "[No trailer]\n";
    }
    os << "\n";

    // Trailer (decoded)
    os << "------ Trailer (decoded) ------\n";
    if (trailer_len >= TRAILER_LEN) {
        PcapWirePrinter::printTrailer(os, trailer, trailer_len);
    } else {
        os << "[Trailer too short to decode]\n";
    }

    os << "\n";
}

std::string PcapDumpWriter::makeFilenameForPort(uint16_t port) {
    return "PcapDump_Side_" + std::to_string(port) + ".txt";
}
