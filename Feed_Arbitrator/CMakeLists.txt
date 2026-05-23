cmake_minimum_required(VERSION 3.16)
project(Feed_Arbitrator LANGUAGES CXX)

# ---------------------------------------------------------
# Global configuration
# ---------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -Wpedantic)

option(ENABLE_DEBUG_PRINTS "Enable debug print utilities" OFF)
option(ENABLE_TESTS "Enable building tests" OFF)

if (ENABLE_DEBUG_PRINTS)
    add_compile_definitions(ENABLE_DEBUG_PRINTS)
endif()

# ---------------------------------------------------------
# Core library
# ---------------------------------------------------------
add_library(project_core
    src/Arbitration.cpp
    src/PcapProcessor.cpp
)

target_include_directories(project_core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(project_core PUBLIC pcap)

# ---------------------------------------------------------
# Debug utilities (compiled always, linked only when enabled)
# ---------------------------------------------------------
add_library(project_debug
    src/debug/DebugPerPacketEventLogger.cpp
    src/debug/PcapDumpWriter.cpp
    src/debug/PcapWirePrinter.cpp
    src/debug/PrintFeedDiff.cpp
)

target_include_directories(project_debug PUBLIC
    ${CMAKE_SOURCE_DIR}/src/debug
)

# Link debug utilities into core + main only when enabled
if (ENABLE_DEBUG_PRINTS)
    target_link_libraries(project_core PUBLIC project_debug)
endif()

# ---------------------------------------------------------
# Main executable
# ---------------------------------------------------------
add_executable(feed_arbitrator
    src/main.cpp
)

target_link_libraries(feed_arbitrator PRIVATE
    project_core
)

# Ensure main executable sees debug macro too
if (ENABLE_DEBUG_PRINTS)
    target_link_libraries(feed_arbitrator PRIVATE project_debug)
endif()

# ---------------------------------------------------------
# Tests
# ---------------------------------------------------------
enable_testing()
if (ENABLE_TESTS)
    add_subdirectory(Test)
endif()

