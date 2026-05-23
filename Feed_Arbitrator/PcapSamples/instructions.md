# Flow Traders Take-Home Coding Challenge

## Summary

- You are given packet capture files from CME MDP 3.0 incremental market data channel 310 (ES futures). Side A is on UDP port 14310 and Side B on UDP port 15310.
- Each packet includes a 20-byte Metamako trailer immediately after the UDP payload with hardware timestamps.
- Your task is to perform feed arbitration between the two sides and compute specific statistics.

## Required output

Compute and print to stdout the following statistics:

- Total number of packets per side (A and B)
- Number of packets in A without a corresponding counterpart in B, and vice versa (by exchange sequence number)
- Number of packets where A is faster than B, and where B is faster than A (by comparing Metamako timestamps for matched sequence numbers)
- Average speed advantage (nanoseconds) of A when A is faster, and of B when B is faster, and the average speed advantage of the fastest channel overall, across both channels.

## Input

- Input files: uncompressed pcap files containing UDP payloads for sides A and B.
- Packet timestamping: Use the Metamako trailer appended to each packet (20 bytes).
    - Offset 8: seconds since Unix epoch (4 bytes)
    - Offset 12: nanosecond correction (4 bytes)
- Exchange sequence number: The exchange packet sequence number is at the beginning of the UDP payload, per CME MDP 3.0 SBE Technical Headers (Little Endian).
- CME MDP 3.0 reference: https://cmegroupclientsite.atlassian.net/wiki/spaces/EPICSANDBOX/pages/457638617/MDP+3.0+-+SBE+Technical+Headers

## Program requirements

- Language: C++
- Build/run: Provide a dockerfile which is capable of building and running your code; provide clear build and run instructions (README and/or script).
- Input: Program accepts a single argument: the directory containing the input pcap files. The program must process all relevant pcap files in that directory.
- pcap parsing: You must use libpcap for reading packets.
- Timestamps: Extract timestamps from the Metamako trailer.
- Matching logic: Perform feed arbitration by matching packets by exchange sequence number across sides A and B.
- Output format: Human-readable text to stdout with the statistics listed above, one per line or clearly labeled.

## Design requirements

- A design with proper encapsulation and clear separation of concerns.
- Provide a clean public interface for core components.
- Pay attention to efficiency and memory usage appropriate for low-latency market data processing.
- Include unit tests covering core logic.
- Include a working dockerfile with instructions on how to build and run your app.
- You have been provided with a clang-format file. Please format all of your code prior to submission.

## What to submit

- Source code
- Unit tests
- Dockerfile
- README with:
    - Build instructions
    - Run instructions
    - Results / Expected output example
    - Any assumptions made, design considerations, scope for future improvements
