//This file is for Multi-threaded version. For single-threaded version, see main_No_thread.cpp
/// PcapProcessingHelpers.hpp
#pragma once

#include <vector>
#include <string>
#include <thread>
#include <tuple>
#include "PcapProcessor.hpp"
#include "Types.hpp"
#include <iostream>

/**
 * @brief Process a list of PCAP files in parallel using multiple threads.
 *
 * Each thread owns its own PcapProcessor instance, ensuring:
 *   - zero shared mutable state
 *   - zero locks
 *   - perfect cache locality
 *   - deterministic behavior
 *
 * Work distribution uses static round‑robin partitioning:
 *
 *   If W = number of workers and F = number of files:
 *
 *       Worker w processes files:
 *           w, w + W, w + 2W, ...
 *
 * Example:
 *   files = {f0, f1, f2, f3, f4, f5}
 *   num_workers = 3
 *
 *   Thread 0 → f0, f3
 *   Thread 1 → f1, f4
 *   Thread 2 → f2, f5
 *
 * This strategy is:
 *   - lock‑free
 *   - contention‑free
 *   - extremely fast
 *   - ideal for HFT‑style workloads
 *
 * @param files List of PCAP file paths.
 * @return tuple:
 *   (merged SideStatsInput A,
 *    merged SideStatsInput B,
 *    detected port A,
 *    detected port B)
 */
inline std::tuple<SideStatsInput, SideStatsInput, uint16_t, uint16_t>
processPcapFilesMultithreaded(const std::vector<std::string>& files)
{
    const std::size_t hw_threads = std::max(1u, std::thread::hardware_concurrency());
    const std::size_t num_workers = std::min(hw_threads, files.size());

    std::vector<PcapProcessor> workers(num_workers);
    std::vector<std::thread> threads;
    threads.reserve(num_workers);

    // -----------------------------
    // 1. Launch worker threads
    // -----------------------------
    for (std::size_t w = 0; w < num_workers; ++w) {
        threads.emplace_back([w, num_workers, &files, &workers]() {
            for (std::size_t i = w; i < files.size(); i += num_workers) {
                const auto& file = files[i];
                if (!workers[w].processFile(file)) {
                    std::cerr << "Warning: error while processing file: " << file << "\n";
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // -----------------------------
    // 2. Discover global ports
    // -----------------------------
    uint16_t globalA = 0;
    uint16_t globalB = 0;

    auto consider = [&](uint16_t p) {
        if (p == 0) return;
        if (globalA == 0) globalA = p;
        else if (p != globalA && globalB == 0) globalB = p;
    };

    for (const auto& w : workers) {
        consider(w.getDetectedPortA());
        consider(w.getDetectedPortB());
    }

    // Optional: enforce deterministic ordering
    if (globalA != 0 && globalB != 0 && globalB < globalA) {
        std::swap(globalA, globalB);
    }

    // -----------------------------
    // 3. Merge by PORT, not by Side enum
    // -----------------------------
    SideStatsInput mergedA;
    SideStatsInput mergedB;

    auto route = [&](uint16_t port, const SideStatsInput& stats) {
        if (port == 0) return;
        if (stats.seq_ts_um.empty()) return;

        if (port == globalA) mergedA.mergeFrom(stats);
        else if (port == globalB) mergedB.mergeFrom(stats);
    };

    for (const auto& w : workers) {
        const uint16_t pa = w.getDetectedPortA();
        const uint16_t pb = w.getDetectedPortB();

        const auto& statsA = w.getSideStats(Side::A);
        const auto& statsB = w.getSideStats(Side::B);

        route(pa, statsA);
        route(pb, statsB);
    }

    return {mergedA, mergedB, globalA, globalB};
}
