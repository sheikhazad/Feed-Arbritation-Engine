// Types.hpp
#pragma once

#include <cstdint>
#include <unordered_map>

/**
 * @brief Logical side of the feed.
 *
 * Side::A and Side::B are assigned dynamically based on the first two
 * distinct UDP destination ports observed in the PCAP.
 */
enum class Side {
    A = 0,
    B = 1
};

/**
 * @brief Per-side statistics collected from PCAP processing.
 *
 * - total_packets: count of packets classified to this side
 * - seq_to_ts: mapping of CME sequence → earliest timestamp (ns)
 */
/*
//Used for single-threaded version. For multi-threaded version, see the updated struct below with mergeFrom method.
struct SideStatsInput {
    uint64_t total_packets{0};
    std::unordered_map<uint64_t, int64_t> seq_ts_um;
};*/

// Updated struct for multi-threaded version with mergeFrom method to combine stats from multiple threads.
struct SideStatsInput {
    uint64_t total_packets{0};
    std::unordered_map<uint64_t, int64_t> seq_ts_um;

    //Multi-thread helper: mergeFrom allows us to combine stats from multiple threads processing different PCAP files for the same side.
    // Merge another side's stats into this one.
    // - total_packets is summed
    // - for each sequence, we keep the earliest timestamp
    void mergeFrom(const SideStatsInput& other) {
        total_packets += other.total_packets;
        for (const auto& [seq, ts] : other.seq_ts_um) {
            auto it = seq_ts_um.find(seq);
            if (it == seq_ts_um.end()) {
                seq_ts_um.emplace(seq, ts);
            } else if (ts < it->second) {
                it->second = ts;
            }
        }
    }
};


/**
 * @brief Summary arbitration result across all sequences.
 *
 * Fields are designed to match the required stdout format exactly:
 *   - Total number of packets per side.
 *   - Unmatched packet counts per side.
 *   - Counts where each side is faster.
 *   - Average speed advantages.
 *   - Overall fastest average advantage.
 */
struct ArbitrationResult {
    uint64_t total_packets_a{0};
    uint64_t total_packets_b{0};

    uint64_t packetsOnlyOnA{0};
    uint64_t packetsOnlyOnB{0};

    uint64_t a_faster_count{0};
    uint64_t b_faster_count{0};

    double a_faster_avg_adv_ns = 0.0;
    double b_faster_avg_adv_ns = 0.0;

    double overall_fastest_avg_adv_ns = 0.0;
};
