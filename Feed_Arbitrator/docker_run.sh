#!/usr/bin/env bash
set -e

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m"

IMAGE_NAME="feed_arbitrator_image"

DEBUG_FLAG=ON
RUN_TESTS=ON
VERBOSE_FLAG=OFF
NO_TESTS=OFF
CLEAN_TESTS_ONLY=OFF
REBUILD_IMAGE=OFF
PCAP_DIR=""
HOST_PCAP_DIR=""

show_help() {
    echo -e "${CYAN}Usage:${NC} ./docker_run.sh [options] <pcap_directory>"
    echo
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  --no-debug         Disable runtime debug and dump in files"
    echo -e "  --no-test          Skip tests"
    echo -e "  --clean-tests-only Clean test artifacts"
    echo -e "  --verbose          Verbose mode"
    echo -e "  --rebuild          Force rebuild of Docker image"
    echo -e "  --help             Show help"
    echo
    exit 0
}

# Parse flags
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --no-debug)
            DEBUG_FLAG=OFF
            ARGS+=("$arg")
            ;;
        --no-test)
            RUN_TESTS=OFF
            NO_TESTS=ON
            ARGS+=("$arg")
            ;;
        --clean-tests-only)
            CLEAN_TESTS_ONLY=ON
            ARGS+=("$arg")
            ;;
        --verbose)
            VERBOSE_FLAG=ON
            ARGS+=("$arg")
            ;;
        --rebuild)
            REBUILD_IMAGE=ON
            ;;
        --help)
            show_help
            ;;
        *)
            if [ -z "$PCAP_DIR" ]; then
                PCAP_DIR="$arg"
            else
                echo -e "${RED}Unexpected argument:${NC} $arg"
                exit 1
            fi
            ;;
    esac
done

# Validate PCAP directory
if [ -z "$PCAP_DIR" ]; then
    echo -e "${RED}Error:${NC} Missing pcap directory."
    exit 1
fi

if [ ! -d "$PCAP_DIR" ]; then
    echo -e "${RED}Error:${NC} Directory '$PCAP_DIR' does not exist."
    exit 1
fi

HOST_PCAP_DIR="$(cd "$PCAP_DIR" && pwd)"

# Ensure Docker installed
if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}Error:${NC} Docker not installed."
    exit 1
fi

# Build image if needed
if [ "$REBUILD_IMAGE" = "ON" ]; then
    echo -e "${BLUE}Rebuilding Docker image (no cache)...${NC}"
    docker build --no-cache -t "$IMAGE_NAME" .
    echo -e "${GREEN}Rebuild complete.${NC}"
else
    if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        echo -e "${BLUE}Building Docker image...${NC}"
        docker build -t "$IMAGE_NAME" .
        echo -e "${GREEN}Image built.${NC}"
    fi
fi

# Verbose mode
if [ "$VERBOSE_FLAG" = "ON" ]; then
    set -x
fi

# Ensure OUTPUT directory exists on host
mkdir -p build/OUTPUT


# Run container
echo -e "${BLUE}Running inside Docker...${NC}"

docker run --rm \
    -e ENABLE_DEBUG_PRINTS="$DEBUG_FLAG" \
    -e RUN_TESTS="$RUN_TESTS" \
    -e NO_TESTS="$NO_TESTS" \
    -v "$HOST_PCAP_DIR":/pcaps \
    -v "$PWD/build/OUTPUT":/output \
    "$IMAGE_NAME" \
    "${ARGS[@]}" /pcaps

echo -e "Note: PCAP Directory in host: ${GREEN}$HOST_PCAP_DIR${NC}"
echo -e "${GREEN}--------------------------- Docker run completed -------------------------${NC}"
