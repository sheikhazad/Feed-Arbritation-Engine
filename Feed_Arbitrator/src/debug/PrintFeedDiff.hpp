#pragma once

#include <cstdint>
#include <unordered_map>
#include <ostream>


//-------------------------------------------------------------------------------------------------------------------//
/**************************This file can be ignored. Its purpose is just debugging and analysis.**********************/
//-------------------------------------------------------------------------------------------------------------------//

/**
 * @brief Side-by-side diff tool for CME MDP 3.0 Side A / Side B comparison.
 * 
 * Functions are ordered in the same order as the diff pipeline:
 *   0. Sequence collection and sorting
 *   1. Side-by-side diff printing
 */
class PrintFeedDiff {
public:
    /**
     * @brief 1. Compare Side A and Side B and print a side-by-side diff table.
     *
     * @param sideA Map: seq → timestamp_ns for Side A.
     * @param sideB Map: seq → timestamp_ns for Side B.
     * @param portA UDP port number representing Side A (dynamic side name).
     * @param portB UDP port number representing Side B (dynamic side name).
     * @param os    Output stream to write the diff into.
     */
    static void compareFeedSides(const std::unordered_map<uint64_t, int64_t>& sideA,
                               const std::unordered_map<uint64_t, int64_t>& sideB,
                               uint16_t portA,
                               uint16_t portB,
                               std::ostream& os);
};
