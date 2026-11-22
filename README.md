# Unfold

[![ci](https://github.com/rcaelers/unfold/actions/workflows/build.yml/badge.svg)](https://github.com/rcaelers/unfold/actions/workflows/build.yml)

## Cross-compiling

Configure Unfold with the target platform's CMake toolchain. Sigstore handles
its own Protobuf library and code generator: a matching host-native `protoc`
must be on the host's `PATH`, or selected with `Protobuf_PROTOC_EXECUTABLE`.
The current Sigstore source fallback requires protoc 36.2.

Applications consuming Unfold do not need to declare or patch Sigstore or
Protobuf. See [Sigstore's cross-compilation instructions](https://github.com/rcaelers/sigstore-verifier-cpp#cross-compiling)
for selecting an explicit host tool.
