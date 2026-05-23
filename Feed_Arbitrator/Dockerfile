FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libpcap-dev \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Install Python packages for PCAP_GENERATOR
RUN pip3 install --no-cache-dir scapy numpy rich dpkt

# Build with tests + debug enabled
RUN mkdir -p build && cd build && \
    cmake -DENABLE_TESTS=ON -DENABLE_DEBUG_PRINTS=ON .. && \
    make -j$(nproc)


# Run the binary by run.sh script
#ENTRYPOINT ["./build/feed_arbitrator"]
ENTRYPOINT ["./run.sh"]

