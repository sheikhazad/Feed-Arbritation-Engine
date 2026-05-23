#!/usr/bin/env python3
"""
PCAP generator for CME MDP 3.0–style incremental feeds with Metamako trailer.

Generates two PCAP files:
  - SideA.pcap
  - SideB.pcap

Each packet:
  - UDP payload starts with 4‑byte little‑endian sequence number
  - Followed by optional padding bytes (to simulate payload)
  - Followed by a 20‑byte Metamako trailer:
      * bytes 0–7: unused
      * bytes 8–11: seconds since Unix epoch (uint32, little‑endian)
      * bytes 12–15: nanoseconds (uint32, little‑endian)
      * bytes 16–19: unused

You can control:
  - total packets
  - fraction of missing packets on each side
  - fraction of out‑of‑order packets
  - base latency and jitter between sides
  - payload size
"""

import argparse
import random
import struct
from typing import List, Tuple

from scapy.all import Ether, IP, UDP, Raw, wrpcap  # type: ignore


def make_metamako_trailer(sec: int, nsec: int) -> bytes:
    """
    Build a 20‑byte Metamako trailer.

    Layout:
      0–7   : unused (zeros)
      8–11  : seconds since epoch (uint32, little‑endian)
      12–15 : nanoseconds (uint32, little‑endian)
      16–19 : unused (zeros)
    """
    return (
        b"\x00" * 8
        + struct.pack(">I", sec)
        + struct.pack(">I", nsec)

        + b"\x00" * 4
    )


def make_cme_packet(
    seq: int,
    sec: int,
    nsec: int,
    dport: int,
    payload_size: int,
    src_ip: str,
    dst_ip: str,
) -> Ether:
    """
    Build a single CME‑style packet with:

      - 4‑byte little‑endian sequence number at start of UDP payload
      - optional padding bytes to reach payload_size
      - 20‑byte Metamako trailer appended after payload
    """
    # Sequence number at offset 0 (little‑endian)
    payload = struct.pack("<I", seq)

    # Optional padding to simulate real payload
    if payload_size > 4:
        payload += b"\xAA" * (payload_size - 4)

    trailer = make_metamako_trailer(sec, nsec)

    pkt = (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=10000, dport=dport)
        / Raw(load=payload + trailer)
    )

    # pcap timestamp (Scapy uses this for the PCAP record header)
    pkt.time = sec + nsec * 1e-9
    return pkt


def generate_sequence_plan(
    total_packets: int,
    missing_a: float,
    missing_b: float,
    out_of_order: float,
    rng: random.Random,
) -> Tuple[List[int], List[int]]:
    """
    Decide which sequence numbers appear on each side and in what order.

    Returns:
      (seqs_a, seqs_b) — lists of sequence numbers in the order they will appear.
    """
    all_seqs = list(range(1, total_packets + 1))

    # Decide which sequences are missing on each side
    seqs_a = []
    seqs_b = []

    for seq in all_seqs:
        drop_a = rng.random() < missing_a
        drop_b = rng.random() < missing_b

        if not drop_a:
            seqs_a.append(seq)
        if not drop_b:
            seqs_b.append(seq)

    # Apply out‑of‑order shuffling
    def maybe_shuffle(seq_list: List[int]) -> List[int]:
        if not seq_list:
            return seq_list
        if out_of_order <= 0.0:
            return seq_list

        # Simple model: randomly swap some adjacent pairs
        seq_list = seq_list.copy()
        for i in range(len(seq_list) - 1):
            if rng.random() < out_of_order:
                seq_list[i], seq_list[i + 1] = seq_list[i + 1], seq_list[i]
        return seq_list

    seqs_a = maybe_shuffle(seqs_a)
    seqs_b = maybe_shuffle(seqs_b)

    return seqs_a, seqs_b


def generate_pcaps(
    total_packets: int,
    missing_a: float,
    missing_b: float,
    out_of_order: float,
    base_latency_ns: int,
    jitter_ns: int,
    payload_size: int,
    base_sec: int,
    dport_a: int,
    dport_b: int,
    rng_seed: int,
    output_prefix: str,
) -> None:
    """
    Generate SideA and SideB PCAPs with controlled characteristics.
    """
    rng = random.Random(rng_seed)

    seqs_a, seqs_b = generate_sequence_plan(
        total_packets=total_packets,
        missing_a=missing_a,
        missing_b=missing_b,
        out_of_order=out_of_order,
        rng=rng,
    )

    side_a_packets: List[Ether] = []
    side_b_packets: List[Ether] = []

    # For simplicity, we assign a base timestamp per sequence number
    # and then derive A/B timestamps from that.
    base_nsec_per_seq = 1_000  # 1 microsecond between base seqs

    # Map seq -> base time
    base_times = {
        seq: (base_sec, base_nsec_per_seq * seq)
        for seq in range(1, total_packets + 1)
    }

    # Build packets for Side A
    for seq in seqs_a:
        sec, nsec = base_times[seq]

        # Side A is base time
        pkt_a = make_cme_packet(
            seq=seq,
            sec=sec,
            nsec=nsec,
            dport=dport_a,
            payload_size=payload_size,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
        )
        side_a_packets.append(pkt_a)

    # Build packets for Side B
    for seq in seqs_b:
        sec, nsec = base_times[seq]

        # Side B time = base + latency + jitter
        jitter = rng.randint(-jitter_ns, jitter_ns) if jitter_ns > 0 else 0
        total_offset = base_latency_ns + jitter
        nsec_b = nsec + total_offset

        # Normalize nsec to [0, 1e9)
        sec_b = sec + nsec_b // 1_000_000_000
        nsec_b = nsec_b % 1_000_000_000

        pkt_b = make_cme_packet(
            seq=seq,
            sec=int(sec_b),
            nsec=int(nsec_b),
            dport=dport_b,
            payload_size=payload_size,
            src_ip="10.0.0.3",
            dst_ip="10.0.0.4",
        )
        side_b_packets.append(pkt_b)

    # Write PCAPs
    out_a = f"{output_prefix}SideA.pcap"
    out_b = f"{output_prefix}SideB.pcap"

    wrpcap(out_a, side_a_packets)
    wrpcap(out_b, side_b_packets)

    print("PCAP generation complete.")
    print(f"  Side A: {out_a}  (packets: {len(side_a_packets)})")
    print(f"  Side B: {out_b}  (packets: {len(side_b_packets)})")
    print()
    print("Summary:")
    print(f"  Total logical sequences: {total_packets}")
    print(f"  Missing on A fraction:   {missing_a:.3f}")
    print(f"  Missing on B fraction:   {missing_b:.3f}")
    print(f"  Out‑of‑order fraction:   {out_of_order:.3f}")
    print(f"  Base latency (ns):       {base_latency_ns}")
    print(f"  Jitter (±ns):            {jitter_ns}")
    print(f"  Payload size (bytes):    {payload_size}")
    print(f"  RNG seed:                {rng_seed}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate CME‑style PCAPs for feed arbitration testing."
    )
    p.add_argument(
        "--total-packets",
        type=int,
        default=1000,
        help="Total logical sequence numbers to generate (default: 1000)",
    )
    p.add_argument(
        "--missing-a",
        type=float,
        default=0.0,
        help="Fraction of sequences missing on Side A (0.0–1.0, default: 0.0)",
    )
    p.add_argument(
        "--missing-b",
        type=float,
        default=0.0,
        help="Fraction of sequences missing on Side B (0.0–1.0, default: 0.0)",
    )
    p.add_argument(
        "--out-of-order",
        type=float,
        default=0.0,
        help="Approx fraction of adjacent swaps to simulate out‑of‑order (0.0–1.0, default: 0.0)",
    )
    p.add_argument(
        "--base-latency-ns",
        type=int,
        default=2000,
        help="Base latency of Side B relative to Side A in nanoseconds (default: 2000)",
    )
    p.add_argument(
        "--jitter-ns",
        type=int,
        default=500,
        help="Max absolute jitter in nanoseconds (default: 500)",
    )
    p.add_argument(
        "--payload-size",
        type=int,
        default=32,
        help="Total UDP payload size in bytes (>=4, default: 32)",
    )
    p.add_argument(
        "--base-sec",
        type=int,
        default=1_700_000_000,
        help="Base seconds since epoch for timestamps (default: 1700000000)",
    )
    p.add_argument(
        "--dport-a",
        type=int,
        default=14310,
        help="UDP destination port for Side A (default: 14310)",
    )
    p.add_argument(
        "--dport-b",
        type=int,
        default=15310,
        help="UDP destination port for Side B (default: 15310)",
    )
    p.add_argument(
        "--rng-seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    p.add_argument(
        "--output-prefix",
        type=str,
        default="",
        help="Optional prefix for output filenames (default: '')",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.payload_size < 4:
        raise ValueError("payload-size must be >= 4 (to hold 4‑byte sequence number)")

    generate_pcaps(
        total_packets=args.total_packets,
        missing_a=args.missing_a,
        missing_b=args.missing_b,
        out_of_order=args.out_of_order,
        base_latency_ns=args.base_latency_ns,
        jitter_ns=args.jitter_ns,
        payload_size=args.payload_size,
        base_sec=args.base_sec,
        dport_a=args.dport_a,
        dport_b=args.dport_b,
        rng_seed=args.rng_seed,
        output_prefix=args.output_prefix,
    )


if __name__ == "__main__":
    main()
