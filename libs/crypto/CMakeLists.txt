add_library(unfold-crypto OBJECT)

target_sources(unfold-crypto PRIVATE
  src/ECDSASignatureAlgorithm.cc
  src/PublicKey.cc
  src/SignatureAlgorithm.cc
  src/SignatureVerifier.cc
  src/SignatureVerifierErrors.cc
)

target_code_coverage(unfold-crypto)

target_link_libraries(unfold-crypto PRIVATE unfold-utils spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(
  unfold-crypto
  PRIVATE
  ${CMAKE_SOURCE_DIR}/libs/crypto/src
  ${boosturl_SOURCE_DIR}/include
  PUBLIC
  ${CMAKE_SOURCE_DIR}/libs/crypto/include)

add_subdirectory(test)
