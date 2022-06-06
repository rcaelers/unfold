add_library(unfold SHARED)

target_sources(unfold PRIVATE
  AppCast.cc
  UpgradeControl.cc
  Checker.cc
  Installer.cc
  UnfoldErrors.cc
  DummyPlatform.cc
  DummySettingsStorage.cc
  Settings.cc
  )

if(APPLE)
  find_library(LIBRARY_COREFOUNDATION CoreFoundation)
  target_link_libraries(unfold PRIVATE ${LIBRARY_COREFOUNDATION})
endif()

if(WIN32)
  target_sources(unfold PRIVATE windows/WindowsPlatform.cc windows/WindowsSettingsStorage.cc)
  target_link_libraries(unfold PUBLIC ws2_32 mswsock)
endif()

target_link_libraries(unfold PUBLIC unfold-utils unfold-crypto unfold-http unfold-coro)
target_link_libraries(unfold PUBLIC Boost::coroutine semver::semver PRIVATE Boost::filesystem spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(unfold PRIVATE BOOST_URL_NO_LIB)

target_include_directories(
  unfold
  PRIVATE
  ${CMAKE_SOURCE_DIR}/include/unfold
  ${CMAKE_SOURCE_DIR}/src
  ${boosturl_SOURCE_DIR}/include
  PUBLIC
  ${CMAKE_SOURCE_DIR}/include)

target_code_coverage(unfold AUTO ALL)

install(TARGETS unfold DESTINATION ${LIBDIR})
