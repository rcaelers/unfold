cmake_minimum_required(VERSION 3.23)
cmake_policy(VERSION 3.23)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

project(Unfold VERSION 0.1 LANGUAGES CXX C)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(IS_TOPLEVEL_PROJECT TRUE)
else()
    set(IS_TOPLEVEL_PROJECT FALSE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

include(FetchContent)
include(GNUInstallDirs)
include(CheckCXXCompilerFlag)

# On Windows, put all DLLs and executables in the same directory
if(WIN32)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

#----------------------------------------------------------------------------------------------------
# Compiler

set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_EXTENSIONS ON)

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
    check_cxx_compiler_flag("-fcoroutines -Werror" HAS_FCOROUTINES)
    if(HAS_FCOROUTINES)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines")
    endif()
endif()

#----------------------------------------------------------------------------------------------------
# Testing

option(UNFOLD_WITH_TESTS "Enable unit tests" ${IS_TOPLEVEL_PROJECT})
include(code-coverage)

set(HAVE_TESTS OFF)
if (UNFOLD_WITH_TESTS)
  set(HAVE_TESTS ON)
  enable_testing()
  add_code_coverage_all_targets(EXCLUDE msys64 _build test HttpServer.cc)
endif()

#----------------------------------------------------------------------------------------------------
# Dependencies

find_package(PkgConfig)
find_package(OpenSSL REQUIRED)

#----------------------------------------------------------------------------------------------------
# Boost

set(BOOST_COMPONENTS filesystem process url json)
set(Boost_DEBUG OFF)

if (WIN32)
  if (NOT(CMAKE_SIZEOF_VOID_P EQUAL 8))
    message(ERROR "Only 64 bit build is supported")
  endif()
endif()

find_package(Boost 1.83.0 REQUIRED COMPONENTS ${BOOST_COMPONENTS})
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})
add_compile_definitions(BOOST_LOG_DYN_LINK BOOST_ASIO_HAS_CO_AWAIT BOOST_BEAST_USE_STD_STRING_VIEW)

#----------------------------------------------------------------------------------------------------
# Logging

find_package(spdlog QUIET)
if(NOT ${spdlog_FOUND})
  FetchContent_Declare(
      spdlog
      GIT_REPOSITORY https://github.com/gabime/spdlog.git
      GIT_SHALLOW TRUE
      GIT_TAG v1.15.2
    )
  set(SPDLOG_BUILD_SHARED ON)
  FetchContent_MakeAvailable(spdlog)
  install(TARGETS spdlog)
endif()
add_definitions(-DSPDLOG_WCHAR_TO_UTF8_SUPPORT)

#----------------------------------------------------------------------------------------------------
# Sigstore

FetchContent_Declare(
  sigstore
  GIT_REPOSITORY https://github.com/rcaelers/sigstore-verifier-cpp
  GIT_TAG a280f24e9c1510117d6a06b591cf84b640fa4b95
)
FetchContent_MakeAvailable(sigstore)

#----------------------------------------------------------------------------------------------------
# Semver

FetchContent_Declare(
  semver
  GIT_REPOSITORY https://github.com/Neargye/semver
  GIT_TAG v0.3.1
)
FetchContent_MakeAvailable(semver)

#----------------------------------------------------------------------------------------------------
# libxml2

find_package(LibXml2 QUIET)

#----------------------------------------------------------------------------------------------------
# XMLSec (optional)

option(UNFOLD_WITH_XMLSEC "Enable XMLSec support for XML digital signature verification" OFF)

if(UNFOLD_WITH_XMLSEC)
  pkg_check_modules(XMLSEC1 REQUIRED IMPORTED_TARGET xmlsec1>=1.3.7)
  pkg_check_modules(XMLSEC1_OPENSSL REQUIRED IMPORTED_TARGET xmlsec1-openssl>=1.3.7)
  add_compile_definitions(UNFOLD_WITH_XMLSEC)
  message(STATUS "XMLSec support enabled")
else()
  message(STATUS "XMLSec support disabled")
endif()

#----------------------------------------------------------------------------------------------------
# Google test/mock

if (UNFOLD_WITH_TESTS)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_SHALLOW TRUE
    GIT_TAG v1.16.0
  )
  # For Windows: Prevent overriding the parent project's compiler/linker settings
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  set(BUILD_SHARED_LIBS ON)
  FetchContent_MakeAvailable(googletest)
endif()

#----------------------------------------------------------------------------------------------------
#

if (WIN32)
  if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-pdb=")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-pdb=")
    add_compile_options(-gdwarf -gcodeview)
  else()
    message(STATUS "Crashpad requires Clang")
  endif()

  file(TO_NATIVE_PATH "${PROJECT_BINARY_DIR}/src" SRC_PATH)
  file(TO_NATIVE_PATH "${CMAKE_INSTALL_PREFIX}/bin" BIN_PATH)
  set(TEST_PATH_ENV "${SRC_PATH};${BIN_PATH};$ENV{PATH}")
  string(REPLACE ";" "\\;" TEST_PATH_ENV "${TEST_PATH_ENV}")
endif()

#----------------------------------------------------------------------------------------------------
#

option(UNFOLD_WITH_GTK3 "Build unfold Gtk+ example" ${IS_TOPLEVEL_PROJECT})
option(UNFOLD_WITH_QT6 "Build unfold Qt6 example" ${IS_TOPLEVEL_PROJECT})

add_subdirectory(libs)
add_subdirectory(src)
add_subdirectory(test)

#----------------------------------------------------------------------------------------------------
# Examples

option(UNFOLD_WITH_EXAMPLES "Build unfold example" ${IS_TOPLEVEL_PROJECT})
add_subdirectory(examples)

#----------------------------------------------------------------------------------------------------
# Install

include(CMakePackageConfigHelpers)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libs/coro/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_package_config_file(
  cmake/${PROJECT_NAME}Config.cmake.in
  ${PROJECT_NAME}Config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

write_basic_package_version_file(
    ${PROJECT_NAME}ConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

install(EXPORT ${PROJECT_NAME}Targets
        NAMESPACE ${PROJECT_NAME}::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
