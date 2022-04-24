cmake_minimum_required(VERSION 3.23)
cmake_policy(VERSION 3.23)

project(unfold VERSION 0.1 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

include(FetchContent)
include(GNUInstallDirs)
include(CheckCXXCompilerFlag)

#----------------------------------------------------------------------------------------------------
# Compiler

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-local-typedef")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
elseif (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")

  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
    list(APPEND EXTRA_LIBRARIES stdc++fs)
  endif()
elseif (${CMAKE_CXX_COMPILER_ID} STREQUAL "Intel")
elseif (${CMAKE_CXX_COMPILER_ID} STREQUAL "MSVC")
endif()

if(NOT MSVC)
    check_cxx_compiler_flag(-fcoroutines HAS_FCOROUTINES)
    if(HAS_FCOROUTINES)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines")
    endif()
endif()

#----------------------------------------------------------------------------------------------------
# Testing

option(WITH_TESTS "Enable unit tests" OFF)

if (WITH_TESTS)
  set(HAVE_TESTS ON)
  enable_testing()
endif()

include(code-coverage)

#----------------------------------------------------------------------------------------------------
# Dependencies

find_package(OpenSSL REQUIRED)

#----------------------------------------------------------------------------------------------------
# Boost

set(Boost_NO_BOOST_CMAKE TRUE)
set(BOOST_COMPONENTS coroutine)
set(Boost_DEBUG OFF)

if (WIN32)
  if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(Boost_ARCHITECTURE "-x64")
  else()
    message(ERROR "Only 64 bit build is supported")
  endif()
endif()

if (HAVE_TESTS)
  set(BOOST_COMPONENTS ${BOOST_COMPONENTS} test_exec_monitor)
endif()

find_package(Boost 1.78.0 REQUIRED COMPONENTS ${BOOST_COMPONENTS})

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})
add_compile_definitions(BOOST_LOG_DYN_LINK BOOST_BEAST_USE_STD_STRING_VIEW)

#----------------------------------------------------------------------------------------------------
# Logging

find_package(spdlog QUIET)
if(NOT ${spdlog_FOUND})
  FetchContent_Declare(
      spdlog
      GIT_REPOSITORY https://github.com/gabime/spdlog.git
      GIT_SHALLOW TRUE
      GIT_TAG v1.10.0
    )
  set(SPDLOG_BUILD_SHARED ON)
  FetchContent_MakeAvailable(spdlog)
endif()

#----------------------------------------------------------------------------------------------------
# Boost URL

FetchContent_Declare(
  boosturl
  GIT_REPOSITORY https://github.com/CPPAlliance/url
  GIT_SHALLOW TRUE
)
FetchContent_Populate(boosturl)

#----------------------------------------------------------------------------------------------------
# Semver

FetchContent_Declare(
  semver
  GIT_REPOSITORY https://github.com/Neargye/semver
  GIT_TAG d3645f7b7d9c0d2d91c9a1e817c4d47ea4ccf514
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(semver)

#----------------------------------------------------------------------------------------------------
# Autoconf compatibility

add_compile_definitions(HAVE_CONFIG_H=1)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
configure_file(${CMAKE_SOURCE_DIR}/cmake/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

#----------------------------------------------------------------------------------------------------
#

add_subdirectory(src)
add_subdirectory(test)
