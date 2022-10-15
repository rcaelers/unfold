add_library(unfold SHARED)
add_library(${PROJECT_NAME}::unfold ALIAS unfold)
set_target_properties(unfold PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS TRUE)

target_sources(unfold PRIVATE
  AppCast.cc
  UpgradeControl.cc
  UpgradeChecker.cc
  UpgradeInstaller.cc
  UnfoldErrors.cc
  Settings.cc
  Hooks.cc
  UnfoldInternalErrors.cc
  )

if(APPLE)
  find_library(LIBRARY_COREFOUNDATION CoreFoundation)
  target_link_libraries(unfold PRIVATE ${LIBRARY_COREFOUNDATION})
endif()

if(WIN32)
  target_sources(unfold PRIVATE windows/WindowsPlatform.cc windows/WindowsSettingsStorage.cc)
  target_link_libraries(unfold PUBLIC ws2_32 mswsock)
endif()

target_link_libraries(unfold PRIVATE unfold-utils unfold-crypto unfold-http unfold-coro)
target_link_libraries(unfold PRIVATE Boost::coroutine semver::semver Boost::filesystem spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(unfold PRIVATE BOOST_URL_NO_LIB)

target_include_directories(
  unfold
  PRIVATE
  ${PROJECT_SOURCE_DIR}/include/unfold
  ${PROJECT_SOURCE_DIR}/src
  ${boosturl_SOURCE_DIR}/include
  PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/libs/coro/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_code_coverage(unfold ALL AUTO)

install(TARGETS unfold
  EXPORT ${PROJECT_NAME}Targets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )
