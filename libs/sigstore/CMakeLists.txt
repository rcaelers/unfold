add_library(unfold-sigstore OBJECT)

target_sources(unfold-sigstore PRIVATE
  src/JsonUtils.cc
  src/SigstoreVerifier.cc
  src/SigstoreErrors.cc
  src/SigstoreBundleBase.cc
  src/SigstoreLegacyBundle.cc
  src/SigstoreStandardBundle.cc
  src/TransparencyLogEntry.cc
  src/TransparencyLogVerifier.cc
  src/CertificateStore.cc
  src/Certificate.cc
  src/PublicKey.cc
  src/CryptographicAlgorithms.cc
  src/RFC6962Hasher.cc
  src/MerkleTreeValidator.cc
)

target_link_libraries(unfold-sigstore PRIVATE unfold-utils unfold-http spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto Boost::json)

target_include_directories(
  unfold-sigstore
  PRIVATE
  ${PROJECT_SOURCE_DIR}/libs/sigstore/src
  ${PROJECT_SOURCE_DIR}/libs/sigstore/include
  ${boosturl_SOURCE_DIR}/include
  PUBLIC
  ${PROJECT_SOURCE_DIR}/libs/sigstore/include)

target_code_coverage(unfold-sigstore ALL AUTO)

add_subdirectory(test)
