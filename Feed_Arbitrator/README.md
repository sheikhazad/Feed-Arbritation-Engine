Note: For simplicity, This C++ code does not focus on low latency features like cacheline, lock free data structures, atomic, prefetch, SIMD, multi threading etc.

# Feed Arbitration for CME MDP 3.0 (ES Futures)

This project processes CME MDP 3.0 multicast market data packets from Side A and Side B, performs feed arbitration, and computes timing statistics using Metamako hardware timestamps. The system matches packets by exchange sequence number, determines which side delivers earlier, and reports latency advantages. Implemented in C++17 with libpcap for packet parsing. 
Optional debug & dump utilities and unit tests are included.

---

## PCAP_GENERATOR Directory

The `PCAP_GENERATOR` directory provides a Python-based toolset for producing synthetic CME-style Side A and Side B PCAP files. It can generate controlled packet streams with configurable jitter, latency offsets, packet loss, and out‑of‑order behavior, enabling deterministic testing of C++ arbitration logic. It also includes utilities for computing expected arbitration statistics which can be used to validate C++ output. Full usage instructions and scenario examples are documented in:

`PCAP_GENERATOR/README_PCAP_GEN.md`

---

## File Structure

Feed_Arbitrator/
│
├── CMakeLists.txt
├── Dockerfile
├── README.md
├── build.sh
├── run.sh
├── docker_run.sh
│
├── src/
│   ├── main.cpp
│   ├── Types.hpp
│   ├── Arbitration.hpp
│   ├── Arbitration.cpp
│   ├── PcapProcessor.hpp
│   ├── PcapProcessor.cpp
│   └── debug/(optional debugging utilities)
│
├── Test/ (optional unit tests)
│   ├── CMakeLists.txt
│   └── test_summary.cpp
│
├── PcapSamples/(sample PCAP files)
│   ├── sample_a.pcap
│   └── sample_b.pcap
│
└── PCAP_GENERATOR/
    ├── pcap_gen.py
    ├── expected_stats.py
    └── README_PCAP_GEN.md
---

## Core Functionality
----------------------
### Packet Parsing
- Reads uncompressed PCAP files via libpcap  
- Extracts CME MDP 3.0 sequence number (little‑endian)  
- Extracts Metamako timestamp trailer (20 bytes, big‑endian)

### Arbitration Logic
- Matches packets by sequence number  
- Determines faster side per matched packet  
- Computes:
  - Total packets per side  
  - Mismatched packets per side  
  - Faster‑side counts  
  - Average nanosecond advantage (Side A, Side B, overall)

### Optional Debug & dump files under build/OUTPUT
- Per‑packet logs  
- Raw packet dumps  
- Side‑by‑side feed comparison files  

---

## Build Instructions
----------------------
### Dependencies

Ubuntu / Debian:

sudo apt-get update
sudo apt-get install build-essential cmake libpcap-dev

MacOS:

brew install cmake libpcap

---

## build.sh Usage

./build.sh [options]

### Options

  --no-debug         Disable debug prints and pcap dump
  --no-test          Disable building tests
  --verbose          Verbose build (script + CMake + Make)
  --clean-only       Only clean build directory, then exit
  --no-clean         Skip cleaning build directory
  --help             Show help menu

### Examples

./build.sh
./build.sh --no-debug --no-test
./build.sh --verbose
./build.sh --clean-only
./build.sh --no-clean --verbose

### Outputs

- build/feed_arbitrator  
- build/libproject_core.a  
- build/libproject_debug.a (if debug enabled)  
- build/Test/run_tests (if tests enabled)

---

## Run Instructions

PCAP files are expected under a directory passed to `run.sh`.

Example:

PcapSamples/
    sideA_001.pcap
    sideB_001.pcap

---

## run.sh Usage

./run.sh [options] <pcap_directory>


### Options

  --no-debug         Disable runtime debug and dump in files
  --no-test          Skip tests
  --verbose          Verbose mode
  --clean-tests-only Clean test artifacts
  --help             Show help


### Examples

./run.sh PcapSamples
./run.sh --no-debug PcapSamples
./run.sh --no-test PcapSamples
./run.sh --verbose PcapSamples
./run.sh --clean-tests-only


### Behavior Summary

- Auto‑builds if executable `feed_arbitrator` is missing  
- Runs arbitration on provided PCAP directory  
- If debug enabled, copies debug output files into `build/OUTPUT`  
- If tests enabled, runs CTest inside `build/Test`  

---

## docker_run.sh (Automatic Docker Build and Run)

`docker_run.sh` automatically:

1. Builds the Docker image (or rebuilds if `--rebuild` is used)  
2. Runs the container  
3. Mounts the PCAP directory  
4. Mounts host `build/OUTPUT` for debug dumps  
5. Executes feed_arbitrator inside the container  

---

## docker_run.sh Usage

From project directory:

./docker_run.sh [options] <pcap_directory>


### Options

  --no-debug         Disable runtime debug and dump in files
  --no-test          Skip tests
  --clean-tests-only Clean test artifacts
  --verbose          Verbose mode
  --rebuild          Force rebuild of Docker image
  --help             Show help


### Examples

./docker_run.sh PcapSamples
./docker_run.sh --no-debug PcapSamples
./docker_run.sh --no-test PcapSamples
./docker_run.sh --verbose PcapSamples
./docker_run.sh --rebuild PcapSamples

---

## Unit Tests

From build/ directory:

./build/Test/run_tests

CTest is invoked automatically by `run.sh` and `docker_run.sh` unless `--no-test` is used.

---

## Assumptions & Design Notes

- Only Ethernet + IPv4 + UDP packets supported  
- CME sequence number = first 4 bytes of UDP payload (little‑endian)  
- Metamako trailer = 20 bytes appended to packet end  
  - Offset 8: seconds (uint32, big‑endian)  
  - Offset 12: nanoseconds (uint32, big‑endian)  
- Duplicate sequence numbers: earliest timestamp used  
- Arbitration logic isolated and fully unit‑testable
