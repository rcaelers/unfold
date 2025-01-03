find_package(Qt6 COMPONENTS Core Widgets Gui Svg LinguistTools Xml REQUIRED)
qt6_standard_project_setup()
set(CMAKE_AUTORCC ON)
add_executable(qt_example)

target_sources(qt_example PRIVATE
  main.cc
  UpdateDialog.cc
  )

target_link_libraries(qt_example PRIVATE unfold unfold-coro unfold-http unfold-utils)
target_link_libraries(qt_example PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(qt_example PRIVATE cmark  Qt6::Gui Qt6::Widgets Qt6::Svg Qt6::Xml)

target_compile_definitions(qt_example PRIVATE CMARK_NO_SHORT_NAMES)

# TODO: remove hack
if(CODE_COVERAGE)
  target_compile_options(qt_example PRIVATE -fprofile-instr-generate -fcoverage-mapping)
  target_link_options(qt_example PRIVATE -fprofile-instr-generate -fcoverage-mapping)
endif()

if (WIN32)
  if (MSVC)
    target_link_options(qt_example PRIVATE "/SUBSYSTEM:WINDOWS")
  elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set_target_properties(qt_example PROPERTIES LINK_FLAGS "-Wl,--subsystem,windows")
  elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_target_properties(qt_example PROPERTIES COMPILE_FLAGS "-mwindows")
    set_target_properties(qt_example PROPERTIES LINK_FLAGS "-mwindows")
  endif()
endif()

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/workrave.png" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

install(TARGETS qt_example DESTINATION bin)
