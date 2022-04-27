if (HAVE_TESTS)
  add_executable(unfold-test-http UnfoldTestHttp.cc HttpServer.cc)
  target_code_coverage(unfold-test-http AUTO)

  target_link_libraries(unfold-test-http PRIVATE unfold unfold-http unfold-utils)
  target_link_libraries(unfold-test-http PRIVATE Boost::test_exec_monitor)
  target_link_libraries(unfold-test-http PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(unfold-test-http PRIVATE ${EXTRA_LIBRARIES})

  target_include_directories(unfold-test-http PRIVATE ${CMAKE_SOURCE_DIR}/src)

  add_test(NAME unfold-test-http COMMAND unfold-test-http)

  if(WIN32)
    set_tests_properties(unfold-test-http PROPERTIES ENVIRONMENT "PATH=${CMAKE_BINARY_DIR}/src\\;${CMAKE_BINARY_DIR}/bin\\;$ENV{PATH}")
  endif()

  add_executable(unfold-test-http-server TestServer.cc HttpServer.cc)

  target_link_libraries(unfold-test-http-server PRIVATE unfold unfold-utils)
  target_link_libraries(unfold-test-http-server PRIVATE Boost::test_exec_monitor)
  target_link_libraries(unfold-test-http-server PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(unfold-test-http-server PRIVATE ${EXTRA_LIBRARIES})

  target_include_directories(unfold-test-http-server PRIVATE ${CMAKE_SOURCE_DIR}/src)
endif()
