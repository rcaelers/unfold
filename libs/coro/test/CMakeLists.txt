if (HAVE_TESTS)
  # add_executable(coro-test CoroTest.cc)
  # target_link_libraries(coro-test PRIVATE unfold-coro unfold-http unfold-utils)
  # target_link_libraries(coro-test PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)

  add_executable(unfold-test-coro UnfoldTestCoro.cc)

  target_link_libraries(unfold-test-coro PRIVATE unfold-coro unfold-http unfold-utils)
  target_link_libraries(unfold-test-coro PRIVATE Boost::test_exec_monitor)
  target_link_libraries(unfold-test-coro PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(unfold-test-coro PRIVATE ${EXTRA_LIBRARIES})

  add_test(NAME unfold-test-coro COMMAND unfold-test-coro)
  target_code_coverage(unfold-test-coro AUTO EXCLUDE _build libs/utils libs/http test/ clang64/include)

  if(WIN32)
    set_tests_properties(unfold-test-coro PROPERTIES ENVIRONMENT "PATH=${TEST_PATH_ENV}")
  endif()

endif()
