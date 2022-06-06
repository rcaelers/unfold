if(WIN32)
  FetchContent_Declare(
    cmark
    GIT_REPOSITORY https://github.com/commonmark/cmark.git
    GIT_TAG        0.30.2
    GIT_SHALLOW    TRUE
    CMAKE_ARGS CMARK_TESTS=OFF
    )
  set(CMARK_TESTS OFF CACHE INTERNAL "Disable tests")
  FetchContent_MakeAvailable(cmark)

  FetchContent_Declare(
    webview2
    URL  https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/1.0.1072.54
    URL_HASH SHA1=aa8ae9db5015a9184011bb195efc5c8caa58a86b
  )
  FetchContent_MakeAvailable(webview2)

  add_library(webview2 INTERFACE)
  target_include_directories(webview2 INTERFACE "${webview2_SOURCE_DIR}/build/native/include/")
  target_compile_options(webview2 INTERFACE -Wno-unknown-pragmas)

  if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64|AMD64")
    target_link_directories(webview2 INTERFACE ${webview2_SOURCE_DIR}/build/native/x64)
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86|X86")
    target_link_directories(webview2 INTERFACE ${webview2_SOURCE_DIR}/build/native/x86)
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|ARM64")
    target_link_directories(webview2 INTERFACE ${webview2_SOURCE_DIR}/build/native/arm64)
  else()
    message(FATAL_ERROR "Unsupported processor: ${CMAKE_SYSTEM_PROCESSOR}")
  endif()

  target_link_libraries(webview2 INTERFACE WebView2Loader)
endif()

add_executable(gtk_example)
target_code_coverage(gtk_example AUTO)

target_sources(gtk_example PRIVATE
  main.cc
  UpdateDialog.cc
  )

target_link_libraries(gtk_example PRIVATE unfold)
target_link_libraries(gtk_example PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)

if (WIN32)
  target_sources(gtk_example PRIVATE Edge.cc)
  target_link_libraries(gtk_example PRIVATE cmark::cmark webview2 ws2_32 mswsock)
endif()

pkg_check_modules(
  GTK REQUIRED
  gtkmm-3.0>=3.22.0
  gtk+-3.0>=3.22.0)

target_include_directories(gtk_example PRIVATE ${GTK_INCLUDE_DIRS})
target_link_directories(gtk_example PRIVATE ${GTK_LIBRARY_DIRS})
target_link_libraries(gtk_example PRIVATE ${GTK_LIBRARIES})
target_compile_definitions(gtk_example PRIVATE CMARK_NO_SHORT_NAMES)

if (WIN32)
  if (MSVC)
    target_link_options(gtk_example PRIVATE "/SUBSYSTEM:WINDOWS")
  elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set_target_properties(gtk_example PROPERTIES LINK_FLAGS "-Wl,--subsystem,windows")
  elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_target_properties(gtk_example PROPERTIES COMPILE_FLAGS "-mwindows")
    set_target_properties(gtk_example PROPERTIES LINK_FLAGS "-mwindows")
  endif()
endif()
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/workrave.png" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
