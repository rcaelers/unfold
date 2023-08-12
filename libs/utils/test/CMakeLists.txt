if (HAVE_TESTS)
  add_executable(unfold-test-utils UnfoldTestUtils.cc EnumTest.cc)
  target_code_coverage(unfold-test-utils ALL AUTO EXCLUDE _build test/)

  target_link_libraries(unfold-test-utils PRIVATE unfold-utils)
  target_link_libraries(unfold-test-utils PRIVATE Boost::test_exec_monitor)
  target_link_libraries(unfold-test-utils PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(unfold-test-utils PRIVATE ${EXTRA_LIBRARIES})

  target_include_directories(unfold-test-utils PRIVATE ${PROJECT_SOURCE_DIR}/src)

  add_test(NAME unfold-test-utils COMMAND unfold-test-utils)

  if(WIN32)
    set_tests_properties(unfold-test-utils PROPERTIES ENVIRONMENT "PATH=${TEST_PATH_ENV}")
  endif()
endif()
