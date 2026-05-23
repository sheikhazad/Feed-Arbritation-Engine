/*
Uses <filesystem> to scan a directory for .pcap files
Calls PcapProcessor to parse packets
Calls ArbitrationEngine to compute statistics
Prints results to stdout
Generates side-by-side diffs into Diff_Side_<port>.txt files (just for observation/debugging)
*/

// main.cpp
#include "Arbitration.hpp"
#include "PcapProcessor.hpp"
#include <filesystem>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>

#include "PcapProcessingHelpers.hpp" // For multi-threaded processing of PCAP files.

#ifdef ENABLE_DEBUG_PRINTS
#include <PcapDumpWriter.hpp>
#include <PrintFeedDiff.hpp>
#endif

namespace fs = std::filesystem;

/**
 * @brief Collect all .pcap files from the given directory.
 *
 * This function iterates over the directory entries and selects only
 * regular files with the ".pcap" extension. The returned vector contains
 * full paths to each PCAP file.
 *
 * @param dir Path to directory containing PCAP files.
 * @return Vector of absolute/relative paths to .pcap files.
 */
static std::vector<std::string> listPcapFiles(const std::string& dir) {
    //std::vector<fs::path> files; //Cheap: Using fs::path will avoid costly string object creation.
    std::vector<std::string> files; //Expensive: But I use string here for simplicity.

    for (const auto& entry : fs::directory_iterator(dir)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto& path = entry.path();
        if (path.extension() == ".pcap") {
            //files.push_back(path.string()); //It will create costly new string object each time. 

            //Any of following will avoid costly string object creation by constructing in-place.
            //files.emplace_back(path.c_str()); 
            files.emplace_back(path.native()); 
                                            
        }
    }

    return files; //NRVO zero-copy optimization
}

/**
 * @brief Display arbitration results in human-readable format.
 *
 * This function prints the arbitration statistics to stdout,
 * using dynamic naming for sides based on detected UDP ports.
 *
 * @param result  ArbitrationResult containing computed statistics.
 * @param portA   Detected UDP port for Side A (0 if unknown).
 * @param portB   Detected UDP port for Side B (0 if unknown).
 */
void displayArbitrationResult(const ArbitrationResult& result,
                            uint16_t portA,
                            uint16_t portB) {
    // ------------------------------------------------------------
    // Print detected sides using dynamic naming: Side_<portNumber>
    // ------------------------------------------------------------
    std::cout << "Detected sides:\n";
    std::cout << "  Side_" << (portA ? std::to_string(portA) : std::string("unknown"))
              << " (mapped to internal Side A)\n";
    std::cout << "  Side_" << (portB ? std::to_string(portB) : std::string("unknown"))
              << " (mapped to internal Side B)\n\n";

    // Print statistics
    std::cout << "Total number of packets in Side_"
              << (portA ? std::to_string(portA) : std::string("unknown"))
              << ": " << result.total_packets_a << "\n";

    std::cout << "Total number of packets in Side_"
              << (portB ? std::to_string(portB) : std::string("unknown"))
              << ": " << result.total_packets_b << "\n\n";

    std::cout << "Number of Packets in Side_"
              << (portA ? std::to_string(portA) : std::string("unknown"))
              << " without corresponding counterpart in Side_"
              << (portB ? std::to_string(portB) : std::string("unknown"))
              << ": " << result.packetsOnlyOnA << "\n";

    std::cout << "Number of Packets in Side_"
              << (portB ? std::to_string(portB) : std::string("unknown"))
              << " without corresponding counterpart in Side_"
              << (portA ? std::to_string(portA) : std::string("unknown"))
              << ": " << result.packetsOnlyOnB << "\n\n";

    std::cout << "Number of Packets where Side_"
              << (portA ? std::to_string(portA) : std::string("unknown"))
              << " is faster than Side_"
              << (portB ? std::to_string(portB) : std::string("unknown"))
              << ": " << result.a_faster_count << "\n";

    std::cout << "Number of Packets where Side_"
              << (portB ? std::to_string(portB) : std::string("unknown"))
              << " is faster than Side_"
              << (portA ? std::to_string(portA) : std::string("unknown"))
              << ": " << result.b_faster_count << "\n\n";

    std::cout << "Average speed advantage of Side_"
              << (portA ? std::to_string(portA) : std::string("unknown"))
              << " when faster (ns): "
              << static_cast<long long>(result.a_faster_avg_adv_ns) << "\n";

    std::cout << "Average speed advantage of Side_"
              << (portB ? std::to_string(portB) : std::string("unknown"))
              << " when faster (ns): "
              << static_cast<long long>(result.b_faster_avg_adv_ns) << "\n\n";

    std::cout << "Average speed advantage of the fastest side overall (ns): "
              << static_cast<long long>(result.overall_fastest_avg_adv_ns) << "\n";
    
}

/**
 * @brief It's just for debug and analysis.
 * Generate side-by-side diffs into Diff_Side_<port>.txt files.
 *
 * This function creates diff files for Side A and Side B if both
 * ports are known (non-zero). It uses PrintFeedDiff to generate
 * the diffs based on sequence-to-timestamp mappings.
 *
 * @param portA   Detected UDP port for Side A (0 if unknown).
 * @param portB   Detected UDP port for Side B (0 if unknown).
 * @param side_a  SideStatsInput for Side A.
 * @param side_b  SideStatsInput for Side B.
 */
#ifdef ENABLE_DEBUG_PRINTS
void compareAndPrintFeedSides(uint16_t portA, uint16_t portB, 
                              const SideStatsInput& side_a,
                              const SideStatsInput& side_b) {
    
    if (portA != 0 && portB != 0) {
        const std::string fileA_name =
            std::string("Diff_Side_") + std::to_string(portA) + ".txt";

        const std::string fileB_name =
            std::string("Diff_Side_") + std::to_string(portB) + ".txt";

        std::ofstream diffA(fileA_name, std::ios::app);
        std::ofstream diffB(fileB_name, std::ios::app);

        if (diffA.is_open()) {
            PrintFeedDiff::compareFeedSides(
                side_a.seq_ts_um,
                side_b.seq_ts_um,
                portA,
                portB,
                diffA
            );
        }

        if (diffB.is_open()) {
            PrintFeedDiff::compareFeedSides(
                side_a.seq_ts_um,
                side_b.seq_ts_um,
                portA,
                portB,
                diffB
            );
        }
    }
}
#endif

/**
 * @brief Main entry point for the feed arbitration application.
 *
 * Usage:
 *   ./feed_arbitrator <pcap_directory>
 *
 * The program:
 *   1. Scans the provided directory for .pcap files.
 *   2. Processes each file using PcapProcessor (libpcap-based parsing).
 *   3. Runs ArbitrationEngine on Side A and Side B data.
 *   4. Prints human-readable statistics to stdout.
 *   5. Writes side-by-side diffs into:
 *        Diff_Side_<portA>.txt
 *        Diff_Side_<portB>.txt
 */
int main(int argc, char** argv) {
    std::cout << "DEBUG: Program started\n";

    // Expect exactly one argument by default: the PCAP directory
    // Additional optional argument for debug packet dump limit
    if (argc != 2) {
        std::cerr << "Usage: feed_arbitrator <pcap_directory>\n";
        return 1;
    }

    #ifdef ENABLE_DEBUG_PRINTS
    std::size_t packet_dump_limit = 1; // default
    if (argc >= 3) {
        packet_dump_limit = std::stoul(argv[2]);
    }
    PcapDumpWriter::setMaxPacketsToDump(packet_dump_limit);
    #endif

    //1. Gather all .pcap files inside the directory
    std::string directory = argv[1];
    // Verify that the directory exists and is a directory
    if (!fs::exists(directory) || !fs::is_directory(directory)) {
        std::cerr << "Invalid directory: " << directory << "\n";
        return 1;
    }

    // Gather all .pcap files inside the directory
    std::vector<std::string> files = listPcapFiles(directory);
    if (files.empty()) {
        std::cerr << "No .pcap files found in directory: " << directory << "\n";
        return 1;
    }

    std::cout << "DEBUG: Found " << files.size() << " pcap files\n";

    //2. Process all PCAP files and fill SideStatsInput structures
    //2.1 Synchronous [single thread]
    /*
    PcapProcessor processor;
    for (const auto& aFile : files) {
        // Each file is processed independently; errors are reported but do not abort all processing
        if (!processor.processFile(aFile)) {
            std::cerr << "Warning: error while processing file: " << aFile << "\n";
        }
    } //We have read and processed all pcap files in the given directory.

    // Retrieve processed statistics for Side A and Side B
    const SideStatsInput& side_a = processor.getSideStats(Side::A);
    const SideStatsInput& side_b = processor.getSideStats(Side::B);

    //3. Run arbitration logic on the collected data
    /*
    //3.1 Synchronous [single thread] - Starts -----//
    ArbitrationEngine engine;
    ArbitrationResult result = engine.compute(side_a, side_b);

    // Dynamically detected ports for Side A and Side B.
    // If no packets were seen for a side, the port will be 0.
    const uint16_t portA = processor.getDetectedPortA();
    const uint16_t portB = processor.getDetectedPortB();

    //4. Display results
    displayArbitrationResult(result, portA, portB);

    //3.1 & 4 Synchronous [single thread] - Ends -----//
    */

    //2. Process all PCAP files and fill SideStatsInput structures
    //2.2 Asynchronous [multi thread]
    auto [mergedA, mergedB, portA, portB] =
    processPcapFilesMultithreaded(files);
    std::cout << "DEBUG: Finished multithreaded processing\n";


    // 3. Run arbitration logic on the collected data
    // 3.2 Asynchronous [multi thread]
    ArbitrationEngine engine;
    ArbitrationResult result = engine.compute(mergedA, mergedB);

    //4. Display results
    displayArbitrationResult(result, portA, portB);

   
#ifdef ENABLE_DEBUG_PRINTS  //Just for observation/debugging, can be ignored
     //compareAndPrintFeedSides(portA, portB, side_a, side_b); //Single threaded version
     compareAndPrintFeedSides(portA, portB, mergedA, mergedB); //Multi threaded version
#endif

    return 0;
}
