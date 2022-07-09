add_library(unfold-coro OBJECT)

target_sources(unfold-coro PRIVATE
  src/IOContext.cc
)

pkg_check_modules (GLIB glib-2.0)

target_link_libraries(unfold-coro PRIVATE spdlog::spdlog)
target_link_libraries(unfold-coro INTERFACE ${EXTRA_LIBRARIES} ${GLIB_LINK_LIBRARIES})
target_include_directories(unfold-coro INTERFACE ${GLIB_INCLUDE_DIRS})

target_include_directories(
  unfold-coro
  PUBLIC
  ${PROJECT_SOURCE_DIR}/libs/coro/include)

add_subdirectory(test)
