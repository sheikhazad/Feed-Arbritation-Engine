#include <catch2/catch_all.hpp>
#include <string>
#include <filesystem>

#include "PcapProcessor.hpp"
#include "Arbitration.hpp"
#include "Types.hpp"

namespace fs = std::filesystem;

TEST_CASE("Full pipeline summary matches expected values") {
    
    const char* env = std::getenv("PCAP_DIR"); 
    REQUIRE(env != nullptr); 
    std::string pcap_dir = env; 

    REQUIRE(fs::exists(pcap_dir));
    REQUIRE(fs::is_directory(pcap_dir));

    // Collect .pcap files
    std::vector<std::string> files;
    for (const auto& entry : fs::directory_iterator(pcap_dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".pcap") {
            files.push_back(entry.path().string());
        }
    }

    REQUIRE(!files.empty());

    // Process all PCAP files
    PcapProcessor proc;
    for (const auto& f : files) {
        REQUIRE(proc.processFile(f));
    }

    const SideStatsInput& sideA = proc.getSideStats(Side::A);
    const SideStatsInput& sideB = proc.getSideStats(Side::B);

    ArbitrationEngine engine;
    ArbitrationResult r = engine.compute(sideA, sideB);

    // Validate final expected numbers
    REQUIRE(r.total_packets_a == 22627);
    REQUIRE(r.total_packets_b == 22627);

    REQUIRE(r.packetsOnlyOnA == 0);
    REQUIRE(r.packetsOnlyOnB == 0);

    REQUIRE(r.a_faster_count == 20430);
    REQUIRE(r.b_faster_count == 2197);

    REQUIRE(static_cast<long long>(r.a_faster_avg_adv_ns) == 2105);
    REQUIRE(static_cast<long long>(r.b_faster_avg_adv_ns) == 759);

    REQUIRE(static_cast<long long>(r.overall_fastest_avg_adv_ns) == 1974);
}
