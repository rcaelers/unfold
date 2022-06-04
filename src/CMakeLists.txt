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

target_code_coverage(unfold)

if(APPLE)
  find_library(LIBRARY_COREFOUNDATION CoreFoundation)
  target_link_libraries(unfold PRIVATE ${LIBRARY_COREFOUNDATION})
endif()

if(WIN32)
  target_sources(unfold PRIVATE windows/WindowsPlatform.cc windows/WindowsSettingsStorage.cc)
  target_link_libraries(unfold PUBLIC ws2_32 mswsock)
endif()

target_link_libraries(unfold PRIVATE unfold-utils unfold-crypto unfold-http)
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

target_compile_definitions(unfold
  PUBLIC
	BOOST_ASIO_HAS_CO_AWAIT
  BOOST_BEAST_USE_STD_STRING_VIEW)

install(TARGETS unfold DESTINATION ${LIBDIR})
