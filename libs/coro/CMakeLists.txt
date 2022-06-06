add_library(unfold-coro INTERFACE)

pkg_check_modules (GLIB glib-2.0)

target_link_libraries(unfold-coro INTERFACE ${EXTRA_LIBRARIES} ${GLIB_LINK_LIBRARIES})
target_include_directories(unfold-coro INTERFACE ${GLIB_INCLUDE_DIRS})

target_include_directories(
  unfold-coro
  INTERFACE
  ${CMAKE_SOURCE_DIR}/libs/coro/include)

add_subdirectory(test)
