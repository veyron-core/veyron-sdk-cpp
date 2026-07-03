cmake_minimum_required(VERSION 3.20)
project(veyron_sdk
    VERSION 0.1.0
    DESCRIPTION "C++ SDK for writing Veyron plugins"
    HOMEPAGE_URL "https://github.com/veyron-core/veyron"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(Protobuf REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(absl REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZSTD REQUIRED IMPORTED_TARGET libzstd)

# Generate C++ bindings from the shared proto
set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/veyron_protocol.proto)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILE})

add_library(veyron_sdk_cpp STATIC
    src/client.cpp
    src/framing.cpp
    src/mac.cpp
    src/env.cpp
    include/veyron/client.hpp
    include/veyron/framing.hpp
    include/veyron/mac.hpp
    include/veyron/plugin.hpp
    include/veyron/env.hpp
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)

add_library(veyron::sdk ALIAS veyron_sdk_cpp)

target_include_directories(veyron_sdk_cpp
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(veyron_sdk_cpp
    PUBLIC
    protobuf::libprotobuf
    absl::base
    absl::strings
    absl::log_internal_check_op
    OpenSSL::Crypto
    PkgConfig::ZSTD
    Threads::Threads
)

# ── Tests ──────────────────────────────────────────────────────────────────
include(CTest)
find_package(GTest REQUIRED)

add_executable(veyron_sdk_tests tests/test_mac.cpp tests/test_env.cpp tests/test_plugin.cpp tests/test_plugin_ping.cpp)
target_link_libraries(veyron_sdk_tests
    PRIVATE
    veyron_sdk_cpp
    GTest::GTest
)
add_test(NAME veyron_sdk_tests COMMAND veyron_sdk_tests)

# ── Examples ───────────────────────────────────────────────────────────────
add_executable(echo_plugin examples/echo_plugin.cpp)
target_link_libraries(echo_plugin PRIVATE veyron_sdk_cpp)

# ── Install ────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(
    TARGETS veyron_sdk_cpp
    EXPORT veyron-sdk-targets
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

install(
    EXPORT veyron-sdk-targets
    FILE veyron-sdk-config.cmake
    NAMESPACE veyron::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/veyron-sdk
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/veyron-sdk-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/veyron-sdk-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/veyron-sdk
)
