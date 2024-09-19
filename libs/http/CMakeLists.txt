add_library(unfold-http OBJECT)

target_sources(unfold-http PRIVATE
  src/HttpClient.cc
  src/HttpStream.cc
  src/HttpClientErrors.cc
  src/HttpServer.cc
  src/Options.cc
)

target_code_coverage(unfold-http ALL AUTO)

if(WIN32)
  target_sources(unfold-http PRIVATE src/windows/WindowsSystemProxy.cc)
  target_link_libraries(unfold-http PUBLIC ws2_32 mswsock crypt32)
endif()

target_link_libraries(unfold-http PUBLIC Boost::url PRIVATE unfold-utils spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto winhttp)
target_compile_definitions(unfold-http PRIVATE BOOST_URL_NO_LIB)

target_include_directories(
  unfold-http
  PRIVATE
  ${PROJECT_SOURCE_DIR}/libs/http/src
  ${boosturl_SOURCE_DIR}/include
  PUBLIC
  ${PROJECT_SOURCE_DIR}/libs/http/include)

add_subdirectory(test)
