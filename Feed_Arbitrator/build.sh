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
DEBUG_FLAG=ON
TEST_FLAG=ON
VERBOSE_FLAG=OFF
CLEAN_ONLY=OFF
NO_CLEAN=OFF

show_help() {
    echo -e "${CYAN}Usage:${NC} ./build.sh [options]"
    echo
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  ${GREEN}--no-debug${NC}     Disable debug prints & pcap dump"
    echo -e "  ${GREEN}--no-test${NC}      Disable building tests"
    echo -e "  ${GREEN}--verbose${NC}      Verbose build (script + CMake + Make)"
    echo -e "  ${GREEN}--clean-only${NC}   Only clean build directory, then exit"
    echo -e "  ${GREEN}--no-clean${NC}     Skip cleaning build directory"
    echo -e "  ${GREEN}--help${NC}         Show this help menu"
    echo
    exit 0
}

# Parse flags
for arg in "$@"; do
    case $arg in
        --no-debug|-debug)
            DEBUG_FLAG=OFF
            ;;
        --no-test)
            TEST_FLAG=OFF
            ;;
        --verbose)
            VERBOSE_FLAG=ON
            ;;
        --clean-only)
            CLEAN_ONLY=ON
            ;;
        --no-clean)
            NO_CLEAN=ON
            ;;
        --help)
            show_help
            ;;
        *)
            echo -e "${RED}Unknown option:${NC} $arg"
            exit 1
            ;;
    esac
done

# Verbose mode: shell + CMake + Make
if [ "$VERBOSE_FLAG" = "ON" ]; then
    set -x
    CMAKE_VERBOSE_BOOL=ON
    MAKE_VERBOSE_FLAG="VERBOSE=1"
else
    CMAKE_VERBOSE_BOOL=OFF
    MAKE_VERBOSE_FLAG=""
fi

# ---------------------------------------------------------
# SAFE CLEANUP BLOCK (macOS-proof)
# ---------------------------------------------------------
safe_clean() {
    if [ -d "$BUILD_DIR" ]; then
        chflags -R nouchg,noschg "$BUILD_DIR" 2>/dev/null || true
        xattr -cr "$BUILD_DIR" 2>/dev/null || true

        rm -rf "$BUILD_DIR" 2>/dev/null || {
            echo -e "${YELLOW}Warning:${NC} build directory could not be fully removed on first attempt."
            echo -e "${YELLOW}Retrying with inode-based forced cleanup...${NC}"

            BUILD_INODE=$(ls -id "$BUILD_DIR" | awk '{print $1}')
            find . -inum "$BUILD_INODE" -exec rm -rf {} + 2>/dev/null || true
        }
    fi
}

# ---------------------------------------------------------
# CLEAN-ONLY MODE
# ---------------------------------------------------------
if [ "$CLEAN_ONLY" = "ON" ]; then
    echo -e "${BLUE}Cleaning build directory (clean-only mode)...${NC}"
    safe_clean
    echo -e "${GREEN}Clean-only completed.${NC}"
    exit 0
fi

# ---------------------------------------------------------
# NORMAL CLEAN (unless --no-clean)
# ---------------------------------------------------------
if [ "$NO_CLEAN" = "OFF" ]; then
    echo -e "${BLUE}Cleaning build directory...${NC}"
    safe_clean
else
    echo -e "${YELLOW}Skipping clean step (--no-clean).${NC}"
fi

mkdir -p "$BUILD_DIR"

# ---------------------------------------------------------
# CMAKE CONFIGURE
# ---------------------------------------------------------
echo -e "${BLUE}Running CMake (debug=$DEBUG_FLAG, tests=$TEST_FLAG)...${NC}"
cd "$BUILD_DIR"

cmake \
    -DCMAKE_VERBOSE_MAKEFILE:BOOL="$CMAKE_VERBOSE_BOOL" \
    -DENABLE_DEBUG_PRINTS="$DEBUG_FLAG" \
    -DENABLE_TESTS="$TEST_FLAG" \
    ..

# ---------------------------------------------------------
# BUILD (captured for parsing)
# ---------------------------------------------------------
echo -e "${BLUE}Building...${NC}"

BUILD_LOG=".build_output.log"
rm -f "$BUILD_LOG"

#{
#    make -j4 $MAKE_VERBOSE_FLAG
#} &> "$BUILD_LOG"

make -j4 $MAKE_VERBOSE_FLAG 2>&1 | tee "$BUILD_LOG"

cat "$BUILD_LOG"

# ---------------------------------------------------------
# COLORED WARNING/ERROR PARSING
# ---------------------------------------------------------
echo -e ""
echo -e "${BLUE}==================== BUILD DIAGNOSTICS ====================${NC}"

WARNINGS=$(grep -i "warning" "$BUILD_LOG" || true)
ERRORS=$(grep -i "error" "$BUILD_LOG" || true)

if [ -n "$WARNINGS" ]; then
    echo -e "${YELLOW}Warnings detected:${NC}"
    echo "$WARNINGS" | sed "s/^/  /"
else
    echo -e "${GREEN}No warnings detected.${NC}"
fi

echo -e ""

if [ -n "$ERRORS" ]; then
    echo -e "${RED}Errors detected:${NC}"
    echo "$ERRORS" | sed "s/^/  /"
else
    echo -e "${GREEN}No errors detected.${NC}"
fi

echo -e "${BLUE}===========================================================${NC}"

# ---------------------------------------------------------
# BUILD OUTPUT SUMMARY
# ---------------------------------------------------------
echo -e ""
echo -e "${BLUE}=================== BUILD OUTPUT SUMMARY ===================${NC}"

if [ -f "feed_arbitrator" ]; then
    echo -e "  Main Binary:        ${GREEN}$(pwd)/feed_arbitrator${NC}"
else
    echo -e "  Main Binary:        ${RED}NOT BUILT${NC}"
fi

if [ -f "libproject_core.a" ]; then
    echo -e "  Core Library:       ${GREEN}$(pwd)/libproject_core.a${NC}"
else
    echo -e "  Core Library:       ${RED}NOT BUILT${NC}"
fi

if [ "$DEBUG_FLAG" = "ON" ]; then
    if [ -f "libproject_debug.a" ]; then
        echo -e "  Debug Library:      ${GREEN}$(pwd)/libproject_debug.a${NC}"
    else
        echo -e "  Debug Library:      ${RED}NOT BUILT${NC}"
    fi
else
    echo -e "  Debug Library:      ${YELLOW}(Not built — debug=OFF)${NC}"
fi

if [ "$TEST_FLAG" = "ON" ]; then
    if [ -f "Test/run_tests" ]; then
        echo -e "  Test Runner:        ${GREEN}$(pwd)/Test/run_tests${NC}"
    else
        echo -e "  Test Runner:        ${RED}NOT BUILT${NC}"
    fi
else
    echo -e "  Test Runner:        ${YELLOW}(Not built — test=OFF)${NC}"
fi

echo -e "${BLUE}============================================================${NC}"

# ---------------------------------------------------------
# SUMMARY BLOCK
# ---------------------------------------------------------
echo -e ""
echo -e "${BLUE}==================== BUILD SUMMARY ====================${NC}"
echo -e "  Debug & Dump Prints:       ${GREEN}$DEBUG_FLAG${NC}"
echo -e "  Tests Enabled:             ${GREEN}$TEST_FLAG${NC}"
echo -e "  Verbose Mode:              ${GREEN}$VERBOSE_FLAG${NC}"
echo -e "  Clean Performed:           ${GREEN}$( [ "$NO_CLEAN" = "OFF" ] && echo YES || echo NO )${NC}"
echo -e "  Build Directory:           ${GREEN}$BUILD_DIR${NC}"
echo -e "========================================================"
echo -e ""
echo -e "${GREEN}For more options, run:${NC} ./build.sh --help"
