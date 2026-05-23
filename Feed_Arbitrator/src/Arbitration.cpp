// Arbitration.cpp
#include "Arbitration.hpp"
#include "Types.hpp"

#include <cstdint>

/**
 * @brief Compute summary arbitration statistics for two sides.
 *
 * Matching logic:
 *   - Sequence numbers are used as the matching key.
 *   - A sequence is unmatched on Side A if it appears only in Side B.
 *   - A sequence is unmatched on Side B if it appears only in Side A.
 *
 * Timing comparison:
 *   - For matched sequences:
 *       * If tsA < tsB → Side A is faster for that sequence.
 *       * If tsB < tsA → Side B is faster for that sequence.
 *       * Equal timestamps do not contribute to faster counts.
 *
 * Aggregation:
 *   - Accumulates total advantage (absolute nanoseconds) separately for
 *     sequences where each side is faster.
 *   - Computes average advantages only over sequences where the side was
 *     strictly faster at least once.
 *   - Computes overall fastest average by combining all strictly faster
 *     sequences from both sides.
 *
 * All arithmetic is performed in integer nanoseconds, with averages
 * accumulated in long double for precision and converted to double.
 */
ArbitrationResult ArbitrationEngine::compute(const SideStatsInput& sideA,
                                             const SideStatsInput& sideB) const {
    ArbitrationResult result;

    // 1. Total packet counts are taken directly from the inputs.
    result.total_packets_a = sideA.total_packets;
    result.total_packets_b = sideB.total_packets;

    // 2. Accumulators for average calculations.
    //    long double is used to reduce rounding error when summing many values.
    long double a_total_adv_ns = 0.0L;
    long double b_total_adv_ns = 0.0L;
    long double overall_total_adv_ns = 0.0L;

    uint64_t overall_faster_count{0};

    // 3. Iterate over all sequences present on Side A.
    //    For each sequence, check if it is present on Side B.
    for (const auto& aSeqTime : sideA.seq_ts_um) {
        const uint64_t seqA = aSeqTime.first;
        const int64_t tsA = aSeqTime.second;

        const auto itB = sideB.seq_ts_um.find(seqA);
        if (itB == sideB.seq_ts_um.end()) {
            // Sequence present only on Side A.
            ++result.packetsOnlyOnA;
            continue;
        }

        const int64_t tsB = itB->second;

        // Matched sequence: compare timestamps.
        if (tsA < tsB) {
            // Side A is faster by (tsB - tsA) nanoseconds.
            const int64_t adv = tsB - tsA;
            ++result.a_faster_count;
            a_total_adv_ns += static_cast<long double>(adv);
            overall_total_adv_ns += static_cast<long double>(adv);
            ++overall_faster_count;
        } else if (tsB < tsA) {
            // Side B is faster by (tsA - tsB) nanoseconds.
            const int64_t adv = tsA - tsB;
            ++result.b_faster_count;
            b_total_adv_ns += static_cast<long double>(adv);
            overall_total_adv_ns += static_cast<long double>(adv);
            ++overall_faster_count;
        } else {
            // Equal timestamps: no side is faster for this sequence.
        }
    }// end for Side A sequences

    // 4. Sequences present only on Side B.
    //    We do not need to check if it is present on Side A as it was already done above.
    for (const auto& bSeqTime : sideB.seq_ts_um) {
        const uint64_t seq = bSeqTime.first;
        if (sideA.seq_ts_um.find(seq) == sideA.seq_ts_um.end()) {
            ++result.packetsOnlyOnB;
        }
    }

    // 5. Compute average advantages where applicable.
    if (result.a_faster_count > 0) {
        result.a_faster_avg_adv_ns =
            static_cast<double>(a_total_adv_ns /
                                static_cast<long double>(result.a_faster_count));
    }

    if (result.b_faster_count > 0) {
        result.b_faster_avg_adv_ns =
            static_cast<double>(b_total_adv_ns /
                                static_cast<long double>(result.b_faster_count));
    }

    if (overall_faster_count > 0) {
        result.overall_fastest_avg_adv_ns =
            static_cast<double>(overall_total_adv_ns /
                                static_cast<long double>(overall_faster_count));
    }

    return result;
}
