#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m"

BUILD_DIR="build"
OUTPUT_DIR="OUTPUT"

DEBUG_FLAG=ON
RUN_TESTS=ON
VERBOSE_FLAG=OFF
NO_TESTS=OFF
CLEAN_TESTS_ONLY=OFF
PCAP_DIR=""

show_help() {
    echo -e "${CYAN}Usage:${NC} ./run.sh [options] <pcap_directory>"
    echo
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  --no-debug         Disable runtime debug and dump in files"
    echo -e "  --no-test          Skip tests"
    echo -e "  --verbose          Verbose mode"
    echo -e "  --clean-tests-only Clean test artifacts"
    echo -e "  --help             Show help"
    echo
    exit 0
}

# Auto-regenerate CMake if needed
#If CMakeCache.txt is missing → regenerate
#If CMakeCache.txt is older than CMakeLists.txt → regenerate
#If the build directory is stale → regenerate
#This guarantees CMake is always correct.
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ] || [ "$BUILD_DIR/CMakeCache.txt" -ot "CMakeLists.txt" ]; then
    echo -e "${YELLOW}CMake configuration is stale or missing. Regenerating...${NC}"
    rm -rf "$BUILD_DIR"
    mkdir "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake ..
    cd ..
fi


# Parse flags
for arg in "$@"; do
    case $arg in
        --no-debug)
            DEBUG_FLAG=OFF
            ;;
        --no-test)
            RUN_TESTS=OFF
            NO_TESTS=ON
            ;;
        --verbose)
            VERBOSE_FLAG=ON
            ;;
        --clean-tests-only)
            CLEAN_TESTS_ONLY=ON
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

# CLEAN TESTS ONLY
if [ "$CLEAN_TESTS_ONLY" = "ON" ]; then
    rm -rf "$BUILD_DIR/Testing" "$BUILD_DIR/CTestTestfile.cmake" 2>/dev/null || true
    echo -e "${GREEN}Test cleanup completed.${NC}"
    exit 0
fi

# Validate PCAP directory
if [ -z "$PCAP_DIR" ]; then
    echo -e "${RED}Error:${NC} Missing pcap directory."
    exit 1
fi

if [ ! -d "$PCAP_DIR" ]; then
    echo -e "${RED}Error:${NC} Directory '$PCAP_DIR' does not exist."
    exit 1
fi

PCAP_DIR="$(cd "$PCAP_DIR" && pwd)"

# Rebuild if any source file is newer than the executable
if [ -f "$BUILD_DIR/feed_arbitrator" ]; then
    if find src -type f -newer "$BUILD_DIR/feed_arbitrator" | grep -q .; then
        echo -e "${YELLOW}Source code changed — rebuilding...${NC}"
        ./build.sh --verbose
    fi
else
    echo -e "${YELLOW}Executable missing — building...${NC}"
    ./build.sh --verbose

    if [ ! -f "$BUILD_DIR/feed_arbitrator" ]; then
        echo -e "${RED}Build failed. Please run ./build.sh manually.${NC}"
        exit 1
    fi
fi


# Verbose mode
if [ "$VERBOSE_FLAG" = "ON" ]; then
    set -x
fi

echo -e "${BLUE}Running feed_arbitrator (debug=$DEBUG_FLAG)...${NC}"

cd "$BUILD_DIR"
./feed_arbitrator "$PCAP_DIR"

echo -e "${GREEN}-------------- feed_arbitrator completed --------------${NC}"
echo -e ""

# DEBUG OUTPUT
if [ "$DEBUG_FLAG" = "ON" ]; then
    echo -e ""
    echo -e "${BLUE}================ DEBUG OUTPUT SUMMARY ================${NC}"

    TARGET_OUTPUT="$OUTPUT_DIR"
    mkdir -p "$TARGET_OUTPUT"

    mv PcapDump_* "$TARGET_OUTPUT" 2>/dev/null || true
    mv PerPacketEvent_* "$TARGET_OUTPUT" 2>/dev/null || true
    mv Diff_* "$TARGET_OUTPUT" 2>/dev/null || true

    echo -e "  Debug & dump files are created under: ${GREEN}$BUILD_DIR/$TARGET_OUTPUT${NC}"
    echo -e ""
    ls -1 "$TARGET_OUTPUT" 2>/dev/null || echo -e "  (No debug files found)"

    if [ -f "/.dockerenv" ]; then
        cp "$TARGET_OUTPUT"/* /output 2>/dev/null || true
    fi

else
    echo -e "${YELLOW}Debug not requested (--no-debug).${NC}"
fi

# TESTS
if [ "$NO_TESTS" = "ON" ]; then
    echo -e "${YELLOW}Skipping tests (--no-test).${NC}"
elif [ "$RUN_TESTS" = "ON" ]; then
    if [ ! -f "Test/run_tests" ]; then
        echo -e "${RED}Tests not built.${NC}"
        exit 1
    fi

    export PCAP_DIR
    echo -e "${BLUE}========================TEST RUN==============================${NC}"

    cd Test
    ctest --output-on-failure
    cd ..

    echo -e "${GREEN}-------------- tests completed --------------${NC}"
else
    echo -e "${YELLOW}Tests not requested (--no-test).${NC}"
fi

# SUMMARY
echo -e ""
echo -e "${BLUE}===================== RUN SUMMARY =====================${NC}"
echo -e "  Debug & dump Prints:     ${GREEN}$DEBUG_FLAG${NC}"
echo -e "  Tests Skipped:           ${GREEN}$NO_TESTS${NC}"
echo -e "  Verbose Mode:            ${GREEN}$VERBOSE_FLAG${NC}"
echo -e "  PCAP Directory:          ${GREEN}$PCAP_DIR${NC}"
echo -e "========================================================"

if [ -f "/.dockerenv" ]; then
    HELP_CMD="./docker_run.sh --help"
else
    HELP_CMD="./run.sh --help"
fi

echo -e "${GREEN}For more options, run:${NC} $HELP_CMD"
