#pragma once

#include <cstdint>
#include <cstddef>
#include <ostream>


//-------------------------------------------------------------------------------------------------------------------//
/**************************This file can be ignored. Its purpose is just debugging and analysis.**********************/
//-------------------------------------------------------------------------------------------------------------------//


/**
 * @brief  Utility namespace providing human-readable formatting helpers
 * for Ethernet, IPv4, UDP, payload, and trailer sections.
 *
 * This module performs *no file I/O* and maintains *no global state*.
 * It is a pure formatting helper used by PcapDumpWriter.
 */
namespace PcapWirePrinter {

    /**
     * @brief Print a hex + ASCII dump of a contiguous byte range.
     *
     * Each line contains:
     *   - Offset (4 hex digits)
     *   - Up to 16 bytes in hex
     *   - ASCII representation (printable chars or '.')
     *
     * @param os     Output stream.
     * @param data   Pointer to the first byte.
     * @param length Number of bytes to dump.
     */
    void printHexAscii(std::ostream& os,
                       const uint8_t* data,
                       std::size_t length);

    /**
     * @brief Print Ethernet header fields in human-readable form.
     *
     * @param os   Output stream.
     * @param data Pointer to the start of the Ethernet header (14 bytes).
     */
    void printEthernetHeader(std::ostream& os,
                             const uint8_t* data);

    /**
     * @brief Print IPv4 header fields in human-readable form.
     *
     * @param os     Output stream.
     * @param data   Pointer to the start of the IPv4 header.
     * @param length Total available bytes for the IPv4 header.
     */
    void printIPv4Header(std::ostream& os,
                         const uint8_t* data,
                         std::size_t length);

    /**
     * @brief Print UDP header fields in human-readable form.
     *
     * @param os   Output stream.
     * @param data Pointer to the start of the UDP header (8 bytes).
     */
    void printUDPHeader(std::ostream& os,
                        const uint8_t* data);

    /**
     * @brief Print ASCII-only representation of a payload.
     *
     * Non-printable characters are replaced with '.'.
     *
     * @param os     Output stream.
     * @param data   Pointer to payload bytes.
     * @param length Number of payload bytes.
     */
    void printAsciiOnly(std::ostream& os,
                        const uint8_t* data,
                        std::size_t length);

    /**
     * @brief Print Metamako trailer fields in human-readable form.
     *
     * Trailer format (20 bytes):
     *   - Bytes 8–11:  seconds (big-endian)
     *   - Bytes 12–15: nanoseconds (big-endian)
     *
     * @param os     Output stream.
     * @param data   Pointer to trailer bytes.
     * @param length Trailer length (should be >= 20).
     */
    void printTrailer(std::ostream& os,
                      const uint8_t* data,
                      std::size_t length);

} // namespace PcapWirePrinter
