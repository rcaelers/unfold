add_library(unfold-utils OBJECT)
target_code_coverage(unfold-utils AUTO ALL)

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
  target_link_libraries(unfold-utils PUBLIC ws2_32 mswsock)
endif()

target_link_libraries(unfold-utils PRIVATE spdlog::spdlog)

target_include_directories(
  unfold-utils
  PRIVATE
  ${PROJECT_SOURCE_DIR}/libs/utils/src
  ${boosturl_SOURCE_DIR}/include
  PUBLIC
  ${PROJECT_SOURCE_DIR}/libs/utils/include)

add_subdirectory(test)
