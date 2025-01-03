if(WIN32)
  FetchContent_Declare(
    webview2
    URL https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/1.0.2651.64
    URL_HASH SHA1=e08093bd127686535cf3519011a584664e6d2b75
  )
  FetchContent_MakeAvailable(webview2)

  add_library(webview2 INTERFACE)
  target_include_directories(webview2 INTERFACE "${webview2_SOURCE_DIR}/build/native/include/")
  target_compile_options(webview2 INTERFACE -Wno-unknown-pragmas)

  if (WIN32 AND (NOT MSVC) AND ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang"))
    execute_process(COMMAND ${CMAKE_CXX_COMPILER} -print-target-triple OUTPUT_VARIABLE CLANG_TRIPLE)
    string(REGEX MATCH "x86_64-.*" _clang_is_x86 ${CLANG_TRIPLE})
    if (CLANG_TRIPLE MATCHES "x86_64")
      set(CMAKE_SYSTEM_PROCESSOR "amd64")
    else()
      set(CMAKE_SYSTEM_PROCESSOR "arm64")
    endif()
  endif()

  if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64|AMD64")
    target_link_directories(webview2 INTERFACE ${webview2_SOURCE_DIR}/build/native/x64)
    install(FILES ${webview2_SOURCE_DIR}/runtimes/win-x64/native/WebView2Loader.dll DESTINATION bin)
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86|X86")
    target_link_directories(webview2 INTERFACE ${webview2_SOURCE_DIR}/build/native/x86)
    install(FILES ${webview2_SOURCE_DIR}/runtimes/win-x86/native/WebView2Loader.dll DESTINATION bin)
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|ARM64")
    target_link_directories(webview2 INTERFACE ${webview2_SOURCE_DIR}/build/native/arm64)
    install(FILES ${webview2_SOURCE_DIR}/runtimes/win-arm64/native/WebView2Loader.dll DESTINATION bin)
  else()
    message(FATAL_ERROR "Unsupported processor: ${CMAKE_SYSTEM_PROCESSOR}")
  endif()
  target_link_libraries(webview2 INTERFACE WebView2Loader)
endif()

add_executable(gtk_example)

target_sources(gtk_example PRIVATE
  main.cc
  resources.gresource.xml.c
  UpdateDialog.cc
  )

target_link_libraries(gtk_example PRIVATE unfold unfold-coro unfold-http unfold-utils)
target_link_libraries(gtk_example PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)

if (WIN32)
  target_sources(gtk_example PRIVATE Edge.cc)
  target_link_libraries(gtk_example PRIVATE cmark webview2 ws2_32 mswsock)
endif()

pkg_check_modules(
  GTK REQUIRED
  gtkmm-3.0>=3.22.0
  gtk+-3.0>=3.22.0)

find_program(GLIB_COMPILE_RESOURCES NAMES glib-compile-resources REQUIRED)

target_include_directories(gtk_example PRIVATE ${GTK_INCLUDE_DIRS})
target_link_directories(gtk_example PRIVATE ${GTK_LIBRARY_DIRS})
target_link_libraries(gtk_example PRIVATE ${GTK_LIBRARIES})
target_compile_definitions(gtk_example PRIVATE CMARK_NO_SHORT_NAMES)

# TODO: remove hack
if(CODE_COVERAGE)
  target_compile_options(gtk_example PRIVATE -fprofile-instr-generate -fcoverage-mapping)
  target_link_options(gtk_example PRIVATE -fprofile-instr-generate -fcoverage-mapping)
endif()

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

execute_process(
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	COMMAND ${GLIB_COMPILE_RESOURCES} --generate-dependencies resources.gresource.xml
	OUTPUT_VARIABLE RESOURCES_DEPENDENCIES
)

add_custom_command(
	OUTPUT resources.gresource.xml.c
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	COMMAND ${GLIB_COMPILE_RESOURCES}
	ARGS
    --sourcedir=${CMAKE_CURRENT_SOURCE_DIR}
    --target=${CMAKE_CURRENT_BINARY_DIR}/resources.gresource.xml.c
		--generate-source
		${CMAKE_CURRENT_SOURCE_DIR}/resources.gresource.xml
	VERBATIM
	MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/resources.gresource.xml
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${RESOURCES_DEPENDENCIES}
)

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/workrave.png" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

install(TARGETS gtk_example DESTINATION bin)
