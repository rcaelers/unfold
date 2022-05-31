add_library(unfold-utils OBJECT)

target_sources(unfold-utils PRIVATE
  src/Base64.cc
  src/Logging.cc
  src/TempDirectory.cc
  src/PeriodicTimer.cc
)

if(WIN32)
target_sources(unfold-utils PRIVATE
  src/StringUtils.cc
)
endif()

target_code_coverage(unfold-utils)

target_link_libraries(unfold-utils PRIVATE spdlog::spdlog semver::semver)

target_include_directories(
  unfold-utils
  PRIVATE
  ${CMAKE_SOURCE_DIR}/libs/utils/src
  ${boosturl_SOURCE_DIR}/include
  PUBLIC
  ${CMAKE_SOURCE_DIR}/libs/utils/include)
