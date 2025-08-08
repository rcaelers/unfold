if (HAVE_TESTS)
  add_executable(unfold-test)

  target_sources(unfold-test PRIVATE
                 AppCastTests.cc
                 CheckerTests.cc
                 InstallerTests.cc
                 IntegrationTests.cc
                 SettingsTests.cc
                 TestPlatform.cc
                 UnfoldTest.cc
                 UpgradeControlTests.cc)

  if(WIN32)
    target_sources(unfold-test PRIVATE WindowsTests.cc)
  endif()

  target_link_libraries(unfold-test PRIVATE unfold unfold-coro unfold-crypto unfold-utils unfold-http)
  target_link_libraries(unfold-test PRIVATE gtest_main gmock_main)
  target_link_libraries(unfold-test PRIVATE spdlog::spdlog semver::semver OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(unfold-test PRIVATE ${EXTRA_LIBRARIES})

  target_include_directories(unfold-test PRIVATE ${PROJECT_SOURCE_DIR}/src)

  add_test(NAME unfold-test COMMAND unfold-test)
  target_code_coverage(unfold-test ALL AUTO EXCLUDE _build test/ libs)


  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-canary.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-canary-error.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-canary-sparkle.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/testappcast.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/okappcast.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/invalidappcast.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-tmpl.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-channels.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/junk" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/junk.sigstore" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/installer.sh" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/ec_private.pem" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/ec_public.pem" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-signed.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-sigstore.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-sigstore.xml.sigstore" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/test-signed-installer.exe" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/test-signed-installer.exe.sigstore" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

  add_executable(test-installer TestInstaller.cc)
  #target_link_options(test-installer PRIVATE -static-libgcc -static-libstdc++)

  # if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  #   set_target_properties(test-installer PROPERTIES COMPILE_FLAGS "-Wl,--subsystem,console")
  #   set_target_properties(test-installer PROPERTIES LINK_FLAGS "-Wl,--subsystem,console")
  # elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  #   set_target_properties(test-installer PROPERTIES COMPILE_FLAGS "-mconsole")
  #   set_target_properties(test-installer PROPERTIES LINK_FLAGS "-mconsole")
  # elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  #   set_target_properties(test-installer PROPERTIES COMPILE_FLAGS "/SUBSYSTEM:CONSOLE")
  #   set_target_properties(test-installer PROPERTIES LINK_FLAGS "/SUBSYSTEM:CONSOLE")
  # endif()

  target_compile_definitions(unfold-test PRIVATE TEST_DATA_DIR="${CMAKE_CURRENT_BINARY_DIR}")
  target_compile_definitions(unfold-test PRIVATE TEST_BIN_DIR="${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

  if(WIN32)
    set_tests_properties(unfold-test PROPERTIES
      ENVIRONMENT "PATH=${TEST_PATH_ENV}"
      WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
  else()
    set_tests_properties(unfold-test PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
  endif()
endif()
