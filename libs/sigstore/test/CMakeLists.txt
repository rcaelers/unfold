add_executable(unfold-test-sigstore
  SigstoreTest.cc
  SigstoreBundleTest.cc
  CertificateStoreTest.cc
  CertificateTest.cc
  PublicKeyTest.cc
  TransparencyLogEntryTest.cc
)

target_link_libraries(unfold-test-sigstore
  PRIVATE
  unfold-sigstore
  unfold-utils
  unfold-http
  GTest::gtest_main
  GTest::gmock_main
  spdlog::spdlog
  OpenSSL::SSL
  OpenSSL::Crypto
  Boost::json
)
target_include_directories(unfold-test-sigstore
  PRIVATE
  ${PROJECT_SOURCE_DIR}/libs/sigstore/src
  ${PROJECT_SOURCE_DIR}/libs/sigstore/include
  ${PROJECT_SOURCE_DIR}/libs/utils/include
  ${PROJECT_SOURCE_DIR}/libs/http/include
)

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-sigstore.xml" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-sigstore.xml.sigstore.bundle" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/data/appcast-sigstore.xml.sigstore.new.bundle" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}")

add_test(NAME unfold-test-sigstore COMMAND unfold-test-sigstore)
target_code_coverage(unfold-test-sigstore AUTO ALL)
