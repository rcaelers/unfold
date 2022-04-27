add_library(unfold SHARED)

target_sources(unfold PRIVATE
  AppCast.cc
  )

target_code_coverage(unfold)

if(APPLE)
  find_library(LIBRARY_COREFOUNDATION CoreFoundation)
  target_link_libraries(unfold PRIVATE ${LIBRARY_COREFOUNDATION})
endif()

if(WIN32)
  target_link_libraries(unfold PUBLIC ws2_32 mswsock)
endif()

target_link_libraries(unfold PRIVATE unfold-utils unfold-crypto unfold-http)
target_link_libraries(unfold PUBLIC Boost::coroutine PRIVATE spdlog::spdlog semver::semver OpenSSL::SSL OpenSSL::Crypto)
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


