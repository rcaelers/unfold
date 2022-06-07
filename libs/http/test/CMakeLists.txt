if (HAVE_TESTS)
  add_executable(unfold-test-http UnfoldTestHttp.cc)
  target_code_coverage(unfold-test-http AUTO EXCLUDE _build libs/utils test/)

  target_link_libraries(unfold-test-http PRIVATE unfold-http unfold-utils)
  target_link_libraries(unfold-test-http PRIVATE Boost::test_exec_monitor)
  target_link_libraries(unfold-test-http PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(unfold-test-http PRIVATE ${EXTRA_LIBRARIES})

  target_include_directories(unfold-test-http PRIVATE ${CMAKE_SOURCE_DIR}/src)

  add_test(NAME unfold-test-http COMMAND unfold-test-http)

  if(WIN32)
    set_tests_properties(unfold-test-http PROPERTIES ENVIRONMENT "PATH=${TEST_PATH_ENV}")
  endif()

  add_executable(unfold-test-http-server TestServer.cc)

# TODO: remove hack
if(CODE_COVERAGE)
  target_compile_options(unfold-test-http-server PRIVATE -fprofile-instr-generate -fcoverage-mapping)
  target_link_options(unfold-test-http-server PRIVATE -fprofile-instr-generate -fcoverage-mapping)
endif()

  target_link_libraries(unfold-test-http-server PRIVATE unfold-http unfold-utils)
  target_link_libraries(unfold-test-http-server PRIVATE Boost::test_exec_monitor)
  target_link_libraries(unfold-test-http-server PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(unfold-test-http-server PRIVATE ${EXTRA_LIBRARIES})

  target_include_directories(unfold-test-http-server PRIVATE ${CMAKE_SOURCE_DIR}/src)
endif()
