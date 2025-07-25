set(SIGSTORE_REV  v0.5.0)
set(GOOGLEAPIS_REV f37bfb8159ea687e6c2a6b587f5cf1dada04b9f8)

FetchContent_Declare(sigstore_protos
    GIT_REPOSITORY  https://github.com/sigstore/protobuf-specs.git
    GIT_TAG         ${SIGSTORE_REV}
    GIT_SHALLOW    TRUE
)

FetchContent_Declare(googleapis_protos
    GIT_REPOSITORY  https://github.com/googleapis/googleapis.git
    GIT_TAG         ${GOOGLEAPIS_REV}
    GIT_SHALLOW    FALSE
)

FetchContent_MakeAvailable(sigstore_protos googleapis_protos)

set(SIGSTORE_PROTO_DIR   ${sigstore_protos_SOURCE_DIR})
set(GOOGLEAPIS_PROTO_DIR ${googleapis_protos_SOURCE_DIR})

find_package(Protobuf 6.31.1 REQUIRED)
message(STATUS "Protobuf found: ${Protobuf_VERSION}, protoc=${Protobuf_PROTOC_EXECUTABLE}")

find_package(absl QUIET)
if(NOT absl_FOUND)
  message(STATUS "Abseil not found, fetching compatible version...")
  FetchContent_Declare(
    abseil
    GIT_REPOSITORY https://github.com/abseil/abseil-cpp.git
    GIT_TAG        20250512.0
    GIT_SHALLOW    TRUE
  )
  FetchContent_MakeAvailable(abseil)
endif()

set(GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GENERATED_DIR})

set(Protobuf_IMPORT_DIRS
    ${SIGSTORE_PROTO_DIR}/protos
    ${GOOGLEAPIS_PROTO_DIR}
)

set(SIGSTORE_PROTO_FILES
     ${SIGSTORE_PROTO_DIR}/protos/sigstore_bundle.proto
     ${SIGSTORE_PROTO_DIR}/protos/sigstore_rekor.proto
     ${SIGSTORE_PROTO_DIR}/protos/envelope.proto
     ${SIGSTORE_PROTO_DIR}/protos/sigstore_common.proto
)

protobuf_generate(
    LANGUAGE cpp
    OUT_VAR   SIGSTORE_PROTO_SRCS
    IMPORT_DIRS ${Protobuf_IMPORT_DIRS}
    PROTOC_OUT_DIR ${GENERATED_DIR}
    PROTOS   ${SIGSTORE_PROTO_FILES}
)
set(GOOGLEAPIS_PROTO_FILES
    ${GOOGLEAPIS_PROTO_DIR}/google/api/field_behavior.proto
)

protobuf_generate(
    LANGUAGE cpp
    OUT_VAR   GOOGLEAPI_PROTO_SRCS
    IMPORT_DIRS ${Protobuf_IMPORT_DIRS}
    PROTOC_OUT_DIR ${GENERATED_DIR}
    PROTOS   ${GOOGLEAPIS_PROTO_FILES}
)

add_library(unfold-sigstore OBJECT)

target_sources(unfold-sigstore PRIVATE
  src/BundleHelper.cc
  src/BundleLoader.cc
  src/CanonicalBodyParser.cc
  src/Certificate.cc
  src/CertificateStore.cc
  src/CheckpointParser.cc
  src/CryptographicAlgorithms.cc
  src/MerkleTreeValidator.cc
  src/PublicKey.cc
  src/RFC6962Hasher.cc
  src/SigstoreErrors.cc
  src/SigstoreVerifier.cc
  src/TransparencyLogLoader.cc
  src/TransparencyLogVerifier.cc
  ${SIGSTORE_PROTO_SRCS}
  ${GOOGLEAPI_PROTO_SRCS}
)

target_link_libraries(unfold-sigstore PRIVATE unfold-utils unfold-http spdlog::spdlog OpenSSL::SSL OpenSSL::Crypto Boost::json protobuf::libprotobuf absl::base absl::status absl::strings)

target_include_directories(
  unfold-sigstore
  PRIVATE
  ${PROJECT_SOURCE_DIR}/libs/sigstore/src
  ${PROJECT_SOURCE_DIR}/libs/sigstore/include
  ${boosturl_SOURCE_DIR}/include
  PUBLIC
  ${PROJECT_SOURCE_DIR}/libs/sigstore/include
  $<BUILD_INTERFACE:${GENERATED_DIR}>
  $<BUILD_INTERFACE:${SIGSTORE_PROTO_DIR}>
  $<BUILD_INTERFACE:${GOOGLEAPIS_PROTO_DIR}>
)

target_code_coverage(unfold-sigstore ALL AUTO)

add_subdirectory(test)
