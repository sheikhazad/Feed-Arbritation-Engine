
//-------------------------------------------------------------------------------------------------------------------//
/**************************This file can be ignored. Its purpose is just debugging and analysis.**********************/
//-------------------------------------------------------------------------------------------------------------------//
This Debug & Dump tool generates following files: 

-Diff_Side_<port>.txt           => Shows differences of SideA and SideB
-PerPacketEvent_Side_<port>.txt => Compact per packet info
-PcapDump_Side_<port>.txt       => Exact dump of pcap file contents in both hex and human readable form. 
                                   More explanation below

How to Read PCAP Data Using PcapWirePrinter (Wire‑Order Guide)
This guide explains how to read a PCAP file byte‑by‑byte while comparing it directly with the output from PcapWirePrinter, generate under build/OUTPUT. Everything is arranged in strict wire order, so that we can scroll down the PCAP hex dump and scroll down the PcapWirePrinter output at the same time.

1. Packet Layout on the Wire (CME MDP 3.0 + Metamako Trailer)
Every packet in the PCAP follows this exact structure:
=== Packet #N (caplen=X bytes) ===

[ Ethernet Header   ] 14 bytes
[ IPv4 Header       ] 20–60 bytes (IHL dependent)
[ UDP Header        ] 8 bytes
[ UDP Payload       ] variable
[ Metamako Trailer  ] 20 bytes


PcapWirePrinter functions are ordered exactly the same way.

2. What PcapWirePrinter Prints (in exact wire order):
When ENABLE_DEBUG_PRINTS is enabled, each packet prints:

(A) Full Packet (Raw + Human Readable)

=== RAW PACKET (N bytes) ===
<Wireshark-style hex+ASCII table>

=== HUMAN READABLE PACKET ===
Ethernet Header:
IPv4 Header:
UDP Header:

This corresponds to:

bytes 0–13   → Ethernet
bytes 14–??  → IPv4
bytes ??–??  → UDP


(B) UDP Payload (Raw + Human Readable):

=== RAW UDP PAYLOAD ===
<hex+ASCII>

=== HUMAN READABLE PAYLOAD (ASCII) ===
<printable characters or '.'>

This corresponds to:

bytes after UDP header → before trailer

(C) Metamako Trailer (Raw + Human Readable):
=== RAW METAMAKO TRAILER (20 bytes) ===
<hex+ASCII>

=== HUMAN READABLE TRAILER ===
Seconds:
Nanoseconds:
Tail bytes:

This corresponds to:

last 20 bytes of packet


(D) Timestamp Fields:

Decoded Timestamp:
Human-Readable UTC:
Trailer Fields:

This shows:
raw0 (bytes 0–7 of trailer)
seconds (bytes 8–11)
nanoseconds (bytes 12–15)
tail (bytes 16–19)

3. How to Compare PCAP Hex Dump With PcapWirePrinter Output
Open the PCAP in Wireshark or xxd:

xxd -g1 -c16 packet.bin

Then compare:

Step 1 — Ethernet (first 14 bytes)
Look at bytes 00–0D in the PCAP.
Match them with:

Ethernet Header:
  Dest MAC:
  Src MAC:
  EtherType:


Step 2 — IPv4 Header
Starts at byte 14 (0x0E).
Match:
Version/IHL
Total length
Protocol
Source IP
Destination IP

Step 3 — UDP Header
Starts at:

14 + (IHL * 4)


Match:
Source port
Destination port
Length

Step 4 — UDP Payload
Everything after UDP header until last 20 bytes.
Match:

=== RAW UDP PAYLOAD ===
=== HUMAN READABLE PAYLOAD ===

Step 5 — Metamako Trailer (last 20 bytes)
Match:

=== RAW METAMAKO TRAILER ===
=== HUMAN READABLE TRAILER ===


Step 6 — Timestamp Fields
Match:

Decoded Timestamp:
Human-Readable UTC:
Trailer Fields:


This confirms:
seconds
nanoseconds
tail bytes
raw0 metadata

4.  In This Debugging Flow:

The packet layout and PcapWirePrinter function order are identical.
We can scroll down the PCAP hex dump and scroll down the PcapWirePrinter output and they match byte for byte.
No guessing offsets.
No jumping around the file.
This is exactly how Wireshark internally parses packets — but now we have that power directly in the code.

5. TO DO:
Open PCAP in Wireshark or xxd.
Run program with ENABLE_DEBUG_PRINTS.
Put the outputs side‑by‑side.
Verify each layer:
Ethernet
IPv4
UDP
Payload
Trailer
Timestamp
This will makes debugging CME MDP 3.0 feeds extremely fast.