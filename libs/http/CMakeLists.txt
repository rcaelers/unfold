add_library(unfold-http OBJECT)

target_sources(unfold-http PRIVATE
  src/HttpClient.cc
  src/HttpClientErrors.cc
  src/HttpServer.cc
  src/Connection.cc
)

if(WIN32)
  target_link_libraries(unfold-http PUBLIC ws2_32 mswsock)
endif()

target_link_libraries(unfold-http PUBLIC Boost::coroutine PRIVATE unfold-utils spdlog::spdlog semver::semver OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(unfold-http PRIVATE BOOST_URL_NO_LIB)

target_include_directories(
  unfold-http
  PRIVATE
  ${CMAKE_SOURCE_DIR}/libs/http/src
  ${boosturl_SOURCE_DIR}/include
  PUBLIC
  ${CMAKE_SOURCE_DIR}/libs/http/include)

target_compile_definitions(
  unfold-http
  PUBLIC
	BOOST_ASIO_HAS_CO_AWAIT
  BOOST_BEAST_USE_STD_STRING_VIEW)

add_subdirectory(test)
