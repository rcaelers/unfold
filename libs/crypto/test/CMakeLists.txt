if (HAVE_TESTS)
  add_executable(unfold-test-crypto UnfoldTestCrypto.cc)

  target_link_libraries(unfold-test-crypto PRIVATE unfold unfold-crypto unfold-utils)
  target_link_libraries(unfold-test-crypto PRIVATE Boost::test_exec_monitor)
  target_link_libraries(unfold-test-crypto PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(unfold-test-crypto PRIVATE ${EXTRA_LIBRARIES})

  target_include_directories(unfold-test-crypto PRIVATE ${PROJECT_SOURCE_DIR}/src)

  add_test(NAME unfold-test-crypto COMMAND unfold-test-crypto)
  target_code_coverage(unfold-test-crypto ALL AUTO EXCLUDE _build libs/utils test/)

  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/junk" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/morejunk" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

  if(WIN32)
    set_tests_properties(unfold-test-crypto PROPERTIES ENVIRONMENT "PATH=${TEST_PATH_ENV}")
  endif()
endif()
