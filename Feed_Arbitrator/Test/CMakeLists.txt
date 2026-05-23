include(FetchContent)

# Fetch Catch2 only when tests are enabled
FetchContent_Declare(
    catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2
)

FetchContent_MakeAvailable(catch2)

# Test executable
add_executable(run_tests
    test_summary.cpp
)

target_link_libraries(run_tests PRIVATE
    project_core
    Catch2::Catch2WithMain
    pcap
)

# Link debug utilities only when enabled
if (ENABLE_DEBUG_PRINTS)
    add_library(project_debug_test
        ${CMAKE_SOURCE_DIR}/src/debug/DebugPerPacketEventLogger.cpp
        ${CMAKE_SOURCE_DIR}/src/debug/PcapDumpWriter.cpp
        ${CMAKE_SOURCE_DIR}/src/debug/PcapWirePrinter.cpp
        ${CMAKE_SOURCE_DIR}/src/debug/PrintFeedDiff.cpp
    )

    target_include_directories(project_debug_test PUBLIC
        ${CMAKE_SOURCE_DIR}/src/debug
    )

    target_compile_definitions(project_core PUBLIC ENABLE_DEBUG_PRINTS)
    target_compile_definitions(project_debug_test PUBLIC ENABLE_DEBUG_PRINTS)

    target_link_libraries(feed_arbitrator PRIVATE project_debug_test)
endif()

# Catch2 test discovery
include(Catch)
catch_discover_tests(run_tests)

# Forward PCAP_DIR from environment into test runtime
set_property(TARGET run_tests PROPERTY
    ENVIRONMENT "PCAP_DIR=$ENV{PCAP_DIR}"
)
