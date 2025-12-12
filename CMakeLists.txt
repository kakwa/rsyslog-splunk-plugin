# CMakeLists.txt for omsplunks2s rsyslog plugin and S2S library
#
# Build options: -DBUILD_RSYSLOG_PLUGIN=ON  (default) Build rsyslog plugin
# -DBUILD_S2S_LIB=OFF        Build standalone S2S library -DBUILD_TESTS=OFF
# Build test program -DUSE_SYSTEM_RSYSLOG=OFF   Use system rsyslog headers
# instead of fetching -DENABLE_TLS=ON            Enable TLS support via OpenSSL
#
# Build requirements: - gcc - (optional) libestr development headers if using
# system rsyslog - (optional) OpenSSL development headers for TLS support

cmake_minimum_required(VERSION 3.14)
project(
  omsplunks2s
  VERSION 1.0.0
  DESCRIPTION "Splunk S2S rsyslog output module"
  LANGUAGES C)

# Build options
option(BUILD_RSYSLOG_PLUGIN "Build the rsyslog output plugin" ON)
option(BUILD_S2S_LIB "Build standalone S2S library" OFF)
option(BUILD_TESTS "Build test program" OFF)
option(USE_SYSTEM_RSYSLOG "Use system-installed rsyslog headers" OFF)
option(ENABLE_TLS "Enable TLS support using OpenSSL" ON)

# Rsyslog version to fetch from upstream
set(RSYSLOG_VERSION
    "v8.2412.0"
    CACHE STRING "Rsyslog version tag to fetch")

# Default to Release build
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find pkg-config
find_package(PkgConfig)

# ============================================================================
# Rsyslog Headers Setup
# ============================================================================
if(BUILD_RSYSLOG_PLUGIN)
  if(USE_SYSTEM_RSYSLOG)
    # Try to find rsyslog via pkg-config
    if(PKG_CONFIG_FOUND)
      pkg_check_modules(RSYSLOG rsyslog)
    endif()

    # Fallback to default paths if pkg-config fails
    if(NOT RSYSLOG_FOUND)
      if(EXISTS "/usr/include/rsyslog")
        set(RSYSLOG_INCLUDE_DIRS "/usr/include/rsyslog")
        set(RSYSLOG_FOUND TRUE)
      else()
        message(
          FATAL_ERROR
            "rsyslog headers not found. Install rsyslog-dev package.\n"
            "  Debian/Ubuntu: sudo apt-get install rsyslog-dev libestr-dev\n"
            "  RHEL/CentOS:   sudo dnf install rsyslog-devel libestr-devel")
      endif()
    endif()
  else()
    # Fetch rsyslog from upstream
    include(FetchContent)

    message(STATUS "Fetching rsyslog ${RSYSLOG_VERSION} from upstream...")

    FetchContent_Declare(
      rsyslog
      GIT_REPOSITORY https://github.com/rsyslog/rsyslog.git
      GIT_TAG ${RSYSLOG_VERSION}
      GIT_SHALLOW TRUE
      GIT_PROGRESS TRUE)

    # Only fetch, don't configure/build rsyslog itself
    FetchContent_GetProperties(rsyslog)
    if(NOT rsyslog_POPULATED)
      FetchContent_Populate(rsyslog)
    endif()

    # Set include directories from fetched source
    set(RSYSLOG_INCLUDE_DIRS
        "${rsyslog_SOURCE_DIR}/runtime" "${rsyslog_SOURCE_DIR}"
        "${rsyslog_SOURCE_DIR}/grammar")
    set(RSYSLOG_FOUND TRUE)

    message(STATUS "Rsyslog source: ${rsyslog_SOURCE_DIR}")
  endif()

  # Get rsyslog module directory for installation
  if(PKG_CONFIG_FOUND)
    execute_process(
      COMMAND ${PKG_CONFIG_EXECUTABLE} --variable=pkglibdir rsyslog
      OUTPUT_VARIABLE RSYSLOG_MODDIR
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
  if(NOT RSYSLOG_MODDIR)
    set(RSYSLOG_MODDIR "/usr/lib/rsyslog")
  endif()
endif()

# Find pthreads
find_package(Threads REQUIRED)

# ============================================================================
# JSON-C Library (required by rsyslog headers)
# ============================================================================
if(BUILD_RSYSLOG_PLUGIN AND NOT USE_SYSTEM_RSYSLOG)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(JSON_C json-c)
    if(JSON_C_FOUND)
      message(STATUS "json-c found: ${JSON_C_VERSION}")
      message(STATUS "json-c include: ${JSON_C_INCLUDE_DIRS}")
    endif()
  endif()

  if(NOT JSON_C_FOUND)
    # Try to find json-c manually
    find_path(JSON_C_INCLUDE_DIR json-c/json.h PATHS /usr/include
                                                     /usr/local/include)
    if(JSON_C_INCLUDE_DIR)
      set(JSON_C_INCLUDE_DIRS ${JSON_C_INCLUDE_DIR})
      message(STATUS "json-c include: ${JSON_C_INCLUDE_DIRS}")
    else()
      message(
        FATAL_ERROR
          "json-c not found. Install json-c development package:\n"
          "  Debian/Ubuntu: sudo apt-get install libjson-c-dev\n"
          "  RHEL/CentOS:   sudo dnf install json-c-devel")
    endif()
  endif()
endif()

# ============================================================================
# TLS/OpenSSL Support
# ============================================================================
if(ENABLE_TLS)
  find_package(OpenSSL REQUIRED)
  if(OPENSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
    set(HAVE_OPENSSL TRUE)
  else()
    message(
      FATAL_ERROR
        "OpenSSL not found. Install OpenSSL development package:\n"
        "  Debian/Ubuntu: sudo apt-get install libssl-dev\n"
        "  RHEL/CentOS:   sudo dnf install openssl-devel\n"
        "Or disable TLS with -DENABLE_TLS=OFF")
  endif()
endif()

# Source files
set(S2S_SOURCES s2s.c)
set(S2S_HEADERS s2s.h)

# ============================================================================
# Standalone S2S Library
# ============================================================================
if(BUILD_S2S_LIB)
  # Shared library
  add_library(s2s SHARED ${S2S_SOURCES})
  set_target_properties(
    s2s
    PROPERTIES OUTPUT_NAME "s2s"
               VERSION ${PROJECT_VERSION}
               SOVERSION 1)
  target_include_directories(s2s PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

  if(HAVE_OPENSSL)
    target_compile_definitions(s2s PRIVATE HAVE_OPENSSL)
    target_include_directories(s2s PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(s2s PRIVATE OpenSSL::SSL OpenSSL::Crypto
                                      Threads::Threads)
  endif()

  # Static library
  add_library(s2s_static STATIC ${S2S_SOURCES})
  set_target_properties(s2s_static PROPERTIES OUTPUT_NAME "s2s"
                                              ARCHIVE_OUTPUT_NAME "s2s")
  target_include_directories(s2s_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

  if(HAVE_OPENSSL)
    target_compile_definitions(s2s_static PRIVATE HAVE_OPENSSL)
    target_include_directories(s2s_static PRIVATE ${OPENSSL_INCLUDE_DIR})
  endif()

  # Install libraries
  install(
    TARGETS s2s s2s_static
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
  install(FILES ${S2S_HEADERS} DESTINATION include)
endif()

# ============================================================================
# Rsyslog Plugin
# ============================================================================
if(BUILD_RSYSLOG_PLUGIN)
  add_library(omsplunks2s MODULE omsplunks2s.c s2s.c)

  # Don't add 'lib' prefix to the module
  set_target_properties(omsplunks2s PROPERTIES PREFIX "" OUTPUT_NAME
                                                         "omsplunks2s")

  target_include_directories(
    omsplunks2s PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${RSYSLOG_INCLUDE_DIRS}
                        ${JSON_C_INCLUDE_DIRS})

  target_link_libraries(omsplunks2s PRIVATE Threads::Threads)

  if(HAVE_OPENSSL)
    target_compile_definitions(omsplunks2s PRIVATE HAVE_OPENSSL)
    target_include_directories(omsplunks2s PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(omsplunks2s PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  endif()

  # Install rsyslog module
  install(TARGETS omsplunks2s LIBRARY DESTINATION ${RSYSLOG_MODDIR})
endif()

# ============================================================================
# Test Program
# ============================================================================
if(BUILD_TESTS)
  add_executable(s2s_test s2s_test.c s2s.c)
  target_include_directories(s2s_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(s2s_test PRIVATE Threads::Threads)

  if(HAVE_OPENSSL)
    target_compile_definitions(s2s_test PRIVATE HAVE_OPENSSL)
    target_include_directories(s2s_test PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(s2s_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  endif()
endif()

# ============================================================================
# Info target (similar to make info)
# ============================================================================
add_custom_target(
  info
  COMMAND ${CMAKE_COMMAND} -E echo "CC:              ${CMAKE_C_COMPILER}"
  COMMAND ${CMAKE_COMMAND} -E echo "CFLAGS:          ${CMAKE_C_FLAGS}"
  COMMAND ${CMAKE_COMMAND} -E echo "Build Type:      ${CMAKE_BUILD_TYPE}"
  COMMAND ${CMAKE_COMMAND} -E echo "RSYSLOG_INCLUDE: ${RSYSLOG_INCLUDE_DIRS}"
  COMMAND ${CMAKE_COMMAND} -E echo "RSYSLOG_MODDIR:  ${RSYSLOG_MODDIR}"
  COMMAND ${CMAKE_COMMAND} -E echo ""
  COMMAND ${CMAKE_COMMAND} -E echo "Options:"
  COMMAND ${CMAKE_COMMAND} -E echo
          "  BUILD_RSYSLOG_PLUGIN: ${BUILD_RSYSLOG_PLUGIN}"
  COMMAND ${CMAKE_COMMAND} -E echo "  BUILD_S2S_LIB:        ${BUILD_S2S_LIB}"
  COMMAND ${CMAKE_COMMAND} -E echo "  BUILD_TESTS:          ${BUILD_TESTS}"
  COMMAND ${CMAKE_COMMAND} -E echo
          "  USE_SYSTEM_RSYSLOG:   ${USE_SYSTEM_RSYSLOG}"
  COMMAND ${CMAKE_COMMAND} -E echo "  RSYSLOG_VERSION:      ${RSYSLOG_VERSION}"
  COMMAND ${CMAKE_COMMAND} -E echo "  ENABLE_TLS:           ${ENABLE_TLS}"
  VERBATIM)

# Print configuration summary
message(STATUS "")
message(STATUS "=== omsplunks2s Configuration ===")
message(STATUS "Build type:           ${CMAKE_BUILD_TYPE}")
message(STATUS "Build rsyslog plugin: ${BUILD_RSYSLOG_PLUGIN}")
message(STATUS "Build S2S library:    ${BUILD_S2S_LIB}")
message(STATUS "Build tests:          ${BUILD_TESTS}")
message(STATUS "TLS support:          ${ENABLE_TLS}")
if(HAVE_OPENSSL)
  message(STATUS "OpenSSL version:      ${OPENSSL_VERSION}")
endif()
if(BUILD_RSYSLOG_PLUGIN)
  message(STATUS "Use system rsyslog:   ${USE_SYSTEM_RSYSLOG}")
  if(NOT USE_SYSTEM_RSYSLOG)
    message(STATUS "Rsyslog version:      ${RSYSLOG_VERSION}")
  endif()
  message(STATUS "Rsyslog include:      ${RSYSLOG_INCLUDE_DIRS}")
  message(STATUS "Rsyslog module dir:   ${RSYSLOG_MODDIR}")
endif()
message(STATUS "")
