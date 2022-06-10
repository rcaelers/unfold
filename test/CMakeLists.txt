if (HAVE_TESTS)
  add_executable(unfold-test)

  target_sources(unfold-test PRIVATE
                 AppCastTests.cc
                 CheckerTests.cc
                 InstallerTests.cc
                 TestPlatform.cc
                 UnfoldTest.cc
                 UpgradeControlTests.cc)

  if(WIN32)
    target_sources(unfold-test PRIVATE WindowsTests.cc)
  endif()

  target_link_libraries(unfold-test PRIVATE unfold)
  target_link_libraries(unfold-test PRIVATE Boost::test_exec_monitor gmock_main)
  target_link_libraries(unfold-test PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(unfold-test PRIVATE ${EXTRA_LIBRARIES})

  target_include_directories(unfold-test PRIVATE ${CMAKE_SOURCE_DIR}/src)

  add_test(NAME unfold-test COMMAND unfold-test)
  target_code_coverage(unfold-test AUTO ALL OBJECTS unfold EXCLUDE _build test/)

  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/testappcast.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/okappcast.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/invalidappcast.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/junk" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/installer.sh" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

  add_executable(test-installer TestInstaller.cc)

  if(WIN32)
    set_tests_properties(unfold-test PROPERTIES ENVIRONMENT "PATH=${TEST_PATH_ENV}")
  endif()
endif()
