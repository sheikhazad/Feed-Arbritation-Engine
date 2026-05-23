// Arbitration.hpp
#pragma once

#include "Types.hpp"

/**
 * @brief Summary-based arbitration engine.
 *
 * Computes:
 *   - total packets per side
 *   - unmatched packets per side
 *   - counts where each side is faster
 *   - average speed advantages
 *   - overall fastest average advantage
 *
 * All computations are based on matching CME sequence numbers across sides.
 */
class ArbitrationEngine {
public:
    /**
     * @brief Compute summary arbitration results for two sides.
     *
     * The function:
     *   1. Aggregates total packet counts from inputs.
     *   2. Iterates over all sequences present on either side.
     *   3. Counts unmatched sequences per side.
     *   4. For matched sequences, compares timestamps and accumulates
     *      per-side advantages.
     *   5. Derives average advantages and overall fastest average.
     *
     * No I/O is performed; the caller is responsible for printing.
     *
     * @param sideA Statistics for logical Side A.
     * @param sideB Statistics for logical Side B.
     * @return Summary ArbitrationResult.
     */
    ArbitrationResult compute(const SideStatsInput& sideA,
                              const SideStatsInput& sideB) const;
};
