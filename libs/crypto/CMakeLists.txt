add_library(unfold-crypto OBJECT)

target_sources(unfold-crypto PRIVATE
  src/ECDSASignatureAlgorithm.cc
  src/PublicKey.cc
  src/SignatureAlgorithm.cc
  src/SignatureVerifier.cc
  src/SignatureVerifierErrors.cc
  src/XMLDSigVerifier.cc
  #src/CertificateExtractor.cc
)

target_link_libraries(unfold-crypto PRIVATE unfold-utils spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto imagehlp crypt32 wintrust)
target_link_libraries(unfold-crypto PRIVATE LibXml2::LibXml2 PkgConfig::XMLSEC1 PkgConfig::XMLSEC1_OPENSSL)

target_include_directories(
  unfold-crypto
  PRIVATE
  ${PROJECT_SOURCE_DIR}/libs/crypto/src
  ${boosturl_SOURCE_DIR}/include
  PUBLIC
  ${PROJECT_SOURCE_DIR}/libs/crypto/include)

target_code_coverage(unfold-crypto ALL AUTO)

add_subdirectory(test)
