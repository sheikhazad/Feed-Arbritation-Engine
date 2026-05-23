#include "PcapWirePrinter.hpp"

#include <iomanip>
#include <sstream>
#include <cctype>

#if defined(_WIN32)
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

namespace {


//-------------------------------------------------------------------------------------------------------------------//
/**************************This file can be ignored. Its purpose is just debugging and analysis.**********************/
//-------------------------------------------------------------------------------------------------------------------//


/**
 * @brief Number of bytes per line in hex+ASCII dumps.
 */
constexpr std::size_t BYTES_PER_LINE = 16;

/**
 * @brief Read a big-endian 32-bit integer from a byte pointer.
 *
 * ntohl() requires a uint32_t that is already loaded into a variable.
 * read_be32() is needed when working directly with raw bytes: it reads
 * 4 bytes in big-endian order and constructs the corresponding uint32_t
 * value in host byte order.
 *
 * @param p Pointer to 4 bytes in big-endian order.
 * @return Decoded uint32_t value (normal host-order integer).
 *
 * Example:
 *   Input bytes at p: 0x12 0x34 0x56 0x78 (big-endian)
 *   Returned value:   0x12345678
 *
 * Note: The returned uint32_t has the same numeric value on all architectures;
 *       endianness affects only how the bytes are stored in memory, not the
 *       integer value itself.
 */
inline uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
            static_cast<uint32_t>(p[3]);
}

/**
 * @brief Convert a MAC address (6 bytes) to aa:bb:cc:dd:ee:ff format.
 * Ethernet headers contain 6‑byte MAC addresses for source and destination. 
 * This function formats those 6 bytes into the standard colon-separated hexadecimal string representation.
 */
std::string formatMac(const uint8_t* mac) {
    std::ostringstream oss;
    //std::setfill('0') : If a hex value is only 1 digit (e.g., 0xA), it will pad with a leading zero → "0a".
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) {
            oss << ":";
        }
        oss << std::setw(2) << static_cast<unsigned>(mac[i]);
    }
    return oss.str();
}

/**
 * @brief Convert IPv4 address (network byte order) to dotted-decimal.
 */
std::string formatIPv4(uint32_t ip_be) {
    uint32_t ip = ntohl(ip_be);
    return std::to_string((ip >> 24) & 0xFF) + "." +//extract the first octet.
           //E.g. If ip = 0xC0A8010A (192.168.1.10), ip >> 24 = 0x000000C0 = 192(12x16) and 
            //& 0xFF gives only the last 8 bits(1111 1111), which is still 192 
            //(because C0 & FF = 1100 0000 & 1111 1111 = 1100 0000 = 192).
           std::to_string((ip >> 16) & 0xFF) + "." + //extract the second octet.
           std::to_string((ip >> 8)  & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

} // namespace

// ======================================================================
// Hex + ASCII dump
//[offset]  [hex bytes padded to 16]  [ASCII or dots]
//Example:
//0000  bb 49 b6 01 98 6b 01 fd dc 73 bf 15 58 00 0b 00   .I...k...s..X...
//0010  2e 00 01 00 09 00 97 c6 ff fc dc 73 bf 15 84 00   ...........s....
// ======================================================================

void PcapWirePrinter::printHexAscii(std::ostream& os,
                                    const uint8_t* data,
                                    std::size_t length) {
    for (std::size_t offset = 0; offset < length; offset += BYTES_PER_LINE) {
        const std::size_t line_len =
            std::min(BYTES_PER_LINE, length - offset);

        //1. Right: Print in hex
        //Print 16 bytes(0x10 bytes) per line, with offset at the start. E.g. 0000, 0010, 0020, 0030 (0,16,32,48) etc.
        os << std::setw(4) << std::setfill('0') << std::hex << offset << "  ";

        for (std::size_t i = 0; i < BYTES_PER_LINE; ++i) {
            if (i < line_len) {
                os << std::setw(2)
                   //Treat byte as a normal integer, not a character(uint8_t = typedef of unsigned char).
                   //E.g. If data[offset + i] = 0x41, it will print "41" in hex instead of "A".
                   << static_cast<unsigned>(data[offset + i]) << ' ';
            } else {
                os << "   ";
            }
        }

        os << "  ";

        //2. Left: Print in ASCII (printable characters or dots)
        for (std::size_t i = 0; i < line_len; ++i) {
            const uint8_t ch = data[offset + i];
            // uint8_t is typedef of unsigned char
            // When streamed, unsigned char prints as a CHARACTER, not a number
            // uint8_t ch = 0x41;   // ASCII 'A'
            // std::cout << ch;     // prints: A   (character)
            // std::cout << static_cast<unsigned>(ch); // prints: 65 in decimal, 41 in hex
            // std::cout << static_cast<char>(ch);    // prints: A   (character)
            // uint8_t is considered as number in ternary operation and so need to cast to char to print as character. 
            os << (std::isprint(ch) ? static_cast<char>(ch) : '.');
        }

        os << '\n';
    }

    //Reset formatting to default (decimal, no zero-padding) after hex output.
    os << std::dec << std::setfill(' ');
}

// ======================================================================
// Ethernet header in hex format: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes EtherType
// ======================================================================

void PcapWirePrinter::printEthernetHeader(std::ostream& os,
                                          const uint8_t* data) {
    const uint8_t* dst = data;
    const uint8_t* src = data + 6;
    const uint16_t ethertype =
        ntohs(*reinterpret_cast<const uint16_t*>(data + 12));

    os << "Ethernet Header:\n";
    os << "   Dest MAC: " << formatMac(dst) << "\n";
    os << "   Src  MAC: " << formatMac(src) << "\n";
    os << "   EtherType: 0x"
       << std::hex << std::setw(4) << std::setfill('0')
       << ethertype << std::dec << std::setfill(' ') << "\n";
}

// ======================================================================
// IPv4 header
// ======================================================================

void PcapWirePrinter::printIPv4Header(std::ostream& os,
                                      const uint8_t* data,
                                      std::size_t length) {
    if (length < 20) {
        os << "[Truncated IPv4 header]\n";
        return;
    }

    const uint8_t version_ihl = data[0];
    const uint8_t ihl = version_ihl & 0x0F;
    const std::size_t header_len = static_cast<std::size_t>(ihl) * 4U;

    if (length < header_len) {
        os << "[IPv4 header length exceeds captured bytes]\n";
        return;
    }

    const uint8_t protocol = data[9];
    //Read 4 byes starting at offset 12 for source IP and offset 16 for destination IP
    const uint32_t src_ip =
        *reinterpret_cast<const uint32_t*>(data + 12);
    const uint32_t dst_ip =
        *reinterpret_cast<const uint32_t*>(data + 16);

    os << "IPv4 Header:\n";
    os << "   Header Length: " << header_len << " bytes\n";
    os << "   Protocol:      " << static_cast<unsigned>(protocol) << "\n";
    os << "   Src IP:        " << formatIPv4(src_ip) << "\n";
    os << "   Dst IP:        " << formatIPv4(dst_ip) << "\n";
}

// ======================================================================
// UDP header: 2 bytes src port, 2 bytes dst port, 2 bytes length, 2 bytes checksum
// ======================================================================

void PcapWirePrinter::printUDPHeader(std::ostream& os,
                                     const uint8_t* data) {
    const uint16_t src_port =
        ntohs(*reinterpret_cast<const uint16_t*>(data));
    const uint16_t dst_port =
        ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    const uint16_t length =
        ntohs(*reinterpret_cast<const uint16_t*>(data + 4));

    os << "UDP Header:\n";
    os << "   Src Port: " << src_port << "\n";
    os << "   Dst Port: " << dst_port << "\n";
    os << "   Length:   " << length << "\n";
}

// ======================================================================
// ASCII-only payload
// ======================================================================

void PcapWirePrinter::printAsciiOnly(std::ostream& os,
                                     const uint8_t* data,
                                     std::size_t length) {
    for (std::size_t i = 0; i < length; ++i) {
        const uint8_t ch = data[i];
        os << (std::isprint(ch) ? static_cast<char>(ch) : '.');
    }
    os << '\n';
}

// ======================================================================
// Trailer (Metamako)
// ======================================================================

void PcapWirePrinter::printTrailer(std::ostream& os,
                                   const uint8_t* data,
                                   std::size_t length) {
    if (length < 20) {
        os << "[Trailer too short to decode Metamako timestamp]\n";
        return;
    }

    const uint32_t sec  = read_be32(data + 8);
    const uint32_t nsec = read_be32(data + 12);

    os << "Trailer:\n";
    os << "   Seconds:     " << sec << "\n";
    os << "   Nanoseconds: " << nsec << "\n";
}
