// PrintFeedDiff.cpp
#include <PrintFeedDiff.hpp>
#include <algorithm>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

//-------------------------------------------------------------------------------------------------------------------//
/**************************This file can be ignored. Its purpose is just debugging and analysis.**********************/
//-------------------------------------------------------------------------------------------------------------------//

/**
 * @brief Compare two sides and print a side-by-side diff table.
 *
 *   ==================== 1. Side_<A> vs Side_<B> DIFF ====================
 *   Seq         Side_<A> Timestamp (ns)Side_<B> Timestamp (ns)Δ(ns)
 *   ------------------------------------------------------------------------
 *   <seq>    <tsA>     <tsB>     <delta>
 *
 * Only sequences present on both sides are printed. Sequences missing on
 * either side are skipped to keep the table focused on matched data.
 */
void PrintFeedDiff::compareFeedSides(const std::unordered_map<uint64_t, int64_t>& sideA,
                                   const std::unordered_map<uint64_t, int64_t>& sideB,
                                   uint16_t portA,
                                   uint16_t portB,
                                   std::ostream& os) {
    // 0. Collect and sort all unique sequence numbers.
    std::vector<uint64_t> seqs;
    seqs.reserve(sideA.size() + sideB.size());

    for (const auto& kv : sideA) {
        seqs.push_back(kv.first);
    }
    for (const auto& kv : sideB) {
        seqs.push_back(kv.first);
    }

    std::sort(seqs.begin(), seqs.end());
    seqs.erase(std::unique(seqs.begin(), seqs.end()), seqs.end());

    // 1. Build dynamic side names based on ports.
    const std::string sideA_name = portA ? ("Side_" + std::to_string(portA)) : "Side_unknown";
    const std::string sideB_name = portB ? ("Side_" + std::to_string(portB)) : "Side_unknown";

    // 2. Print header line.
    os << "==================== 1. " << sideA_name
       << " vs " << sideB_name << " DIFF ====================\n";

    // 3. Print column header line.
    os << "Seq         "
       << sideA_name << " Timestamp(ns) "
       << sideB_name << " Timestamp(ns) "
       << "Δ(ns)\n";

    // 4. Print separator line.
    os << "------------------------------------------------------------------------\n";

    // 5. Print each matched sequence.
    for (const uint64_t seq : seqs) {
        const auto itA = sideA.find(seq);
        const auto itB = sideB.find(seq);

        if (itA == sideA.end() || itB == sideB.end()) {
            // Skip sequences that are not present on both sides.
            continue;
        }

        const int64_t tsA = itA->second;
        const int64_t tsB = itB->second;
        const int64_t delta = tsB - tsA;

        os << seq << "    "
           << tsA << "      "
           << tsB << "      "
           << delta << "\n";
    }
}
