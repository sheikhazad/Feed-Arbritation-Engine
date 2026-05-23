#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

struct pcap_pkthdr;


//-------------------------------------------------------------------------------------------------------------------//
/**************************This file can be ignored. Its purpose is just debugging and analysis.**********************/
//-------------------------------------------------------------------------------------------------------------------//


/**
 * @brief Writes a structured, human-learning-oriented dump of PCAP packets.
 * Output file naming:
 *     PcapDump_Side_<port>.txt
 *
 * This module:
 *   - Prints the PCAP filename at the top of each dump file.
 *   - Dumps packets in the exact wire order.
 *   - Uses PcapWirePrinter for all formatting.
 *   - Supports a runtime limit on number of packets to dump per port.
 */
class PcapDumpWriter {
public:
    /**
     * @brief Set the PCAP filename to print at the top of each dump file.
     */
    static void setPcapFilename(const std::string& filename);

    /**
     * @brief Set maximum packets to dump per port.
     *
     * n = 0 → dump all packets.
     * Default = 1.
     */
    static void setMaxPacketsToDump(std::size_t n);

    /**
     * @brief Dump a packet if within the configured limit.
     */
    static void dumpPacket(uint16_t port,
                           const pcap_pkthdr* header,
                           const uint8_t* data);

private:
    /**
     * @brief Construct filename: PcapDump_Side_<port>.txt
     */
    static std::string makeFilenameForPort(uint16_t port);
};
