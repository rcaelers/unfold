if (UNFOLD_WITH_EXAMPLES)
  FetchContent_Declare(
    cmark
    GIT_REPOSITORY https://github.com/commonmark/cmark.git
    GIT_TAG        0.31.1
    GIT_SHALLOW    TRUE
    CMAKE_ARGS "BUILD_TESTING=OFF BUILD_STATIC_LIBS=OFF BUILD_SHARED_LIBS=ON"
  )
  set(BUILD_TESTING OFF CACHE INTERNAL "Disable tests")
  FetchContent_MakeAvailable(cmark)
endif()

if (UNFOLD_WITH_GTK3 AND UNFOLD_WITH_EXAMPLES)
  add_subdirectory(gtk)
endif()

if (UNFOLD_WITH_QT6 AND UNFOLD_WITH_EXAMPLES)
  add_subdirectory(qt)
endif()
