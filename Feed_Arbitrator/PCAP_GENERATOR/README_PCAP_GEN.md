# PCAP Generator for CME‑Style Feed Arbitration Testing

This directory contains a full‑featured PCAP generator designed to create synthetic but structurally accurate CME MDP 3.0 incremental feed packets.  
Generated packets include:

- CME SBE sequence numbers (little‑endian)
- UDP payloads with configurable sizes
- A 20‑byte Metamako timestamp trailer (big‑endian, matching real hardware)
- Side A and Side B packet streams with configurable:
  - packet loss
  - jitter
  - latency differences
  - out‑of‑order delivery
  - reproducible randomness

These PCAPs are intended for validating C++ feed arbitration logic.

---

# 1. Environment Setup
     
1.1. Running docker_run.sh will install Python3 and required packages.
1.2. If we want to run locally:

Create a Python virtual environment:

    python3 -m venv venv
    source venv/bin/activate

Install Scapy:

    pip install scapy

---

# 2. Generating PCAP Files

Run the generator:

    python3 pcap_gen.py

This produces:

- SideA.pcap
- SideB.pcap

Default configuration:

- 1000 packets
- no packet loss
- Side B slower by ~2000 ns ± 500 ns jitter
- payload size 32 bytes

---

# 3. Generator Options

The generator supports the following parameters:

    --total-packets N
    --missing-a FLOAT
    --missing-b FLOAT
    --out-of-order FLOAT
    --base-latency-ns N
    --jitter-ns N
    --payload-size N
    --rng-seed N
    --output-prefix STR

Example:

    python3 pcap_gen.py \
      --total-packets 5000 \
      --missing-a 0.05 \
      --missing-b 0.10 \
      --base-latency-ns 3000 \
      --jitter-ns 1500 \
      --out-of-order 0.02 \
      --payload-size 48 \
      --rng-seed 101

---

# 4. Computing Expected Arbitration Statistics

After generating PCAPs, expected arbitration results can be computed using:

    python3 expected_stats.py SideA.pcap SideB.pcap

This produces a JSON object such as:

    {
      "total_A": 1000,
      "total_B": 1000,
      "unmatched_A": 0,
      "unmatched_B": 0,
      "A_faster": 1000,
      "B_faster": 0,
      "avg_A_adv_ns": 2001.312,
      "avg_B_adv_ns": 0.0,
      "avg_overall_adv_ns": 2001.312
    }

These values represent the ground‑truth statistics for the generated PCAPs.

---

# 5. Realistic PCAP Generation Scenarios

The following scenarios simulate realistic CME multicast feed behavior.

---

## Scenario 1 — Heavy unmatched packets (asymmetric packet loss)

    python3 pcap_gen.py \
      --total-packets 50000 \
      --missing-a 0.15 \
      --missing-b 0.05 \
      --base-latency-ns 3000 \
      --jitter-ns 1500 \
      --out-of-order 0.02 \
      --payload-size 48 \
      --rng-seed 101

---

## Scenario 2 — Extreme jitter with latency flips

    python3 pcap_gen.py \
      --total-packets 30000 \
      --missing-a 0.02 \
      --missing-b 0.02 \
      --base-latency-ns -1000 \
      --jitter-ns 5000 \
      --out-of-order 0.10 \
      --payload-size 64 \
      --rng-seed 202

---

## Scenario 3 — Burst jitter and heavy out‑of‑order delivery

    python3 pcap_gen.py \
      --total-packets 20000 \
      --missing-a 0.00 \
      --missing-b 0.00 \
      --base-latency-ns 2000 \
      --jitter-ns 20000 \
      --out-of-order 0.20 \
      --rng-seed 303

---

## Scenario 4 — Massive unmatched packets (feed outage simulation)

    python3 pcap_gen.py \
      --total-packets 100000 \
      --missing-a 0.40 \
      --missing-b 0.00 \
      --base-latency-ns 1500 \
      --jitter-ns 500 \
      --rng-seed 404

---

## Scenario 5 — CME‑style realistic incremental feed

    python3 pcap_gen.py \
      --total-packets 80000 \
      --missing-a 0.01 \
      --missing-b 0.015 \
      --base-latency-ns 1200 \
      --jitter-ns 800 \
      --out-of-order 0.03 \
      --payload-size 80 \
      --rng-seed 505

---

# 6. Workflow Summary

1. Generate PCAPs:

       python3 pcap_gen.py

2. Compute expected arbitration results:

       python3 expected_stats.py SideA.pcap SideB.pcap

3. Run the C++ arbitrator:

       ./run.sh PCAP_GENERATOR

4. Compare arbitrator output with expected statistics.

---

# 7. Notes

- The Metamako trailer is encoded in big‑endian, matching real hardware.
- CME sequence numbers are little‑endian, matching SBE specification.
- Ethernet MAC warnings from Scapy on macOS are harmless; PCAP generation is unaffected.

