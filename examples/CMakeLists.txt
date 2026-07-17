if (UNFOLD_WITH_EXAMPLES)
  # Prefer system/MSYS2 cmark: CMake package -> FetchContent.
  set(UNFOLD_CMARK_TARGET "")

  find_package(cmark CONFIG QUIET)
  if (TARGET cmark::cmark)
    set(UNFOLD_CMARK_TARGET cmark::cmark)
  elseif (TARGET cmark)
    set(UNFOLD_CMARK_TARGET cmark)
  endif()

  if (NOT UNFOLD_CMARK_TARGET)
    message(STATUS "System cmark not found; using FetchContent")
    FetchContent_Declare(
      cmark
      GIT_REPOSITORY https://github.com/commonmark/cmark.git
      GIT_TAG        0.31.2
      GIT_SHALLOW    TRUE
      CMAKE_ARGS "BUILD_TESTING=OFF BUILD_STATIC_LIBS=OFF BUILD_SHARED_LIBS=ON"
    )
    set(BUILD_TESTING OFF CACHE INTERNAL "Disable tests")
    FetchContent_MakeAvailable(cmark)

    if (TARGET cmark::cmark)
      set(UNFOLD_CMARK_TARGET cmark::cmark)
    elseif (TARGET cmark)
      set(UNFOLD_CMARK_TARGET cmark)
    endif()
  else()
    message(STATUS "Using system cmark")
  endif()

  if (NOT UNFOLD_CMARK_TARGET)
    message(FATAL_ERROR "No cmark target found")
  endif()
endif()

if (UNFOLD_WITH_GTK3 AND UNFOLD_WITH_EXAMPLES)
  add_subdirectory(gtk)
endif()

if (UNFOLD_WITH_QT6 AND UNFOLD_WITH_EXAMPLES)
  add_subdirectory(qt)
endif()
