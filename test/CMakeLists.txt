if (HAVE_TESTS)
  add_executable(unfold-test UnfoldTest.cc HTTPServer.cc)
  target_code_coverage(unfold-test AUTO)

  target_link_libraries(unfold-test PRIVATE unfold)
  target_link_libraries(unfold-test PRIVATE Boost::test_exec_monitor)
  target_link_libraries(unfold-test PRIVATE spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)
  target_link_libraries(unfold-test PRIVATE ${EXTRA_LIBRARIES})

  target_include_directories(unfold-test PRIVATE ${CMAKE_SOURCE_DIR}/src)

  add_test(NAME unfold-test COMMAND unfold-test)

  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/junk" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/morejunk" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/testappcast.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/invalidappcast.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

  if(WIN32)
    set_tests_properties(unfold-test PROPERTIES ENVIRONMENT "PATH=${CMAKE_BINARY_DIR}/src\\;${CMAKE_BINARY_DIR}/bin\\;$ENV{PATH}")
  endif()
endif()
