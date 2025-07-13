// Copyright (C) 2022 Rob Caelers <rob.caelers@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <memory>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#if SPDLOG_VERSION >= 10600
#  include <spdlog/pattern_formatter.h>
#endif
#if SPDLOG_VERSION >= 10801
#  include <spdlog/cfg/env.h>
#endif
#include <spdlog/fmt/ostr.h>

#include "utils/Logging.hh"
#include "crypto/SignatureVerifier.hh"
#include "crypto/SignatureVerifierErrors.hh"

using namespace unfold::crypto;
using namespace unfold::utils;

struct GlobalCryptoTest : public ::testing::Environment
{
  GlobalCryptoTest() = default;
  ~GlobalCryptoTest() override = default;

  GlobalCryptoTest(const GlobalCryptoTest &) = delete;
  GlobalCryptoTest &operator=(const GlobalCryptoTest &) = delete;
  GlobalCryptoTest(GlobalCryptoTest &&) = delete;
  GlobalCryptoTest &operator=(GlobalCryptoTest &&) = delete;

  void SetUp() override
  {
    const auto *log_file = "unfold-test-utils.log";

    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file, false);
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    auto logger{std::make_shared<spdlog::logger>("unfold", std::initializer_list<spdlog::sink_ptr>{file_sink, console_sink})};
    logger->flush_on(spdlog::level::critical);
    spdlog::set_default_logger(logger);

    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%-5l%$] %v");

#if SPDLOG_VERSION >= 10801
    spdlog::cfg::load_env_levels();
#endif
  }

  void TearDown() override
  {
    spdlog::drop_all();
  }
};

::testing::Environment *const global_env = ::testing::AddGlobalTestEnvironment(new GlobalCryptoTest);

struct CryptoTest : public ::testing::Test
{
  CryptoTest() = default;
  ~CryptoTest() override = default;

  CryptoTest(const CryptoTest &) = delete;
  CryptoTest &operator=(const CryptoTest &) = delete;
  CryptoTest(CryptoTest &&) = delete;
  CryptoTest &operator=(CryptoTest &&) = delete;

private:
  std::shared_ptr<spdlog::logger> logger{Logging::create("test")};
};

TEST_F(CryptoTest, signature_verify_file_ok_pem)
{
  // openssl genpkey -algorithm Ed25519 -out ed25519key.pem
  // openssl pkey -in ed25519key.pem -pubout >ed25519pub.pem
  // openssl pkeyutl -sign -inkey ed25519key.pem -out junk.ed25519 -rawin -in junk
  // openssl pkeyutl -verify -pubin -inkey ed25519pub.pem  -rawin -in junk -sigfile junk.ed25519
  // openssl pkey -in ../../test/data/ed25519key.pem -pubout

  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";
  std::string pub_key =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=\n"
    "-----END PUBLIC KEY-----\n";

  SignatureVerifier verifier;
  auto result = verifier.set_key(SignatureAlgorithmType::ECDSA, pub_key);
  EXPECT_EQ(result.has_error(), false);
  result = verifier.verify("junk", signature);
  EXPECT_EQ(result.has_error(), false);
}

TEST_F(CryptoTest, signature_verify_invalid_pem)
{
  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";
  std::string pub_key =
    "-----BEGIN PUBLIC KEY-----\n"
    "VGhpc0lzQW5JbnZhbGlkUGVtQ2VydGlmaWNhdGUK\n"
    "-----END PUBLIC KEY-----\n";

  SignatureVerifier verifier;
  auto result = verifier.set_key(SignatureAlgorithmType::ECDSA, pub_key);
  EXPECT_EQ(result.has_error(), true);
  EXPECT_EQ(result.error(), SignatureVerifierErrc::InvalidPublicKey);
}

TEST_F(CryptoTest, signature_verify_file_ok_der)
{
  // openssl genpkey -algorithm Ed25519 -out ed25519key.pem
  // openssl pkey -in ed25519key.pem -pubout >ed25519pub.pem
  // openssl pkeyutl -sign -inkey ed25519key.pem -out junk.ed25519 -rawin -in junk
  // openssl pkeyutl -verify -pubin -inkey ed25519pub.pem  -rawin -in junk -sigfile junk.ed25519
  // openssl pkey -in ../../test/data/ed25519key.pem -pubout -outform DER | base64

  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";
  std::string pub_key = "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=";

  SignatureVerifier verifier;
  auto result = verifier.set_key(SignatureAlgorithmType::ECDSA, pub_key);
  EXPECT_EQ(result.has_error(), false);
  result = verifier.verify("junk", signature);
  EXPECT_EQ(result.has_error(), false);
}

TEST_F(CryptoTest, signature_verify_invalid_der)
{
  std::string pub_key = "xxxxMCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=xxx";

  SignatureVerifier verifier;
  auto result = verifier.set_key(SignatureAlgorithmType::ECDSA, pub_key);
  EXPECT_EQ(result.has_error(), true);
  EXPECT_EQ(result.error(), SignatureVerifierErrc::InvalidPublicKey);
}

TEST_F(CryptoTest, signature_verify_invalid_signature)
{
  std::string signature;
  std::string pub_key = "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=";

  SignatureVerifier verifier;
  auto result = verifier.set_key(SignatureAlgorithmType::ECDSA, pub_key);
  EXPECT_EQ(result.has_error(), false);
  result = verifier.verify("junk", signature);
  EXPECT_EQ(result.error(), SignatureVerifierErrc::InvalidSignature);
}

TEST_F(CryptoTest, signature_verify_file_nok)
{
  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";
  std::string pub_key =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=\n"
    "-----END PUBLIC KEY-----\n";

  SignatureVerifier verifier;
  auto result = verifier.set_key(SignatureAlgorithmType::ECDSA, pub_key);
  EXPECT_EQ(result.has_error(), false);
  result = verifier.verify("morejunk", signature);
  EXPECT_EQ(result.error(), SignatureVerifierErrc::Mismatch);
}

TEST_F(CryptoTest, signature_verify_file_not_found)
{
  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";
  std::string pub_key =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=\n"
    "-----END PUBLIC KEY-----\n";

  SignatureVerifier verifier;
  auto result = verifier.set_key(SignatureAlgorithmType::ECDSA, pub_key);
  EXPECT_EQ(result.has_error(), false);
  result = verifier.verify("notfound", signature);
  EXPECT_EQ(result.error(), SignatureVerifierErrc::NotFound);
}

TEST_F(CryptoTest, signature_verify_without_algorithm)
{
  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";

  SignatureVerifier verifier;
  auto result = verifier.verify("junk", signature);
  EXPECT_EQ(result.error(), SignatureVerifierErrc::InvalidPublicKey);
}

TEST_F(CryptoTest, signature_verify_without_valid_pubkey)
{
  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";

  SignatureVerifier verifier;
  std::string pub_key = "xxxxMCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=xxx";

  auto result = verifier.set_key(SignatureAlgorithmType::ECDSA, pub_key);
  EXPECT_EQ(result.has_error(), true);
  EXPECT_EQ(result.error(), SignatureVerifierErrc::InvalidPublicKey);

  result = verifier.verify("junk", signature);
  EXPECT_EQ(result.error(), SignatureVerifierErrc::InvalidPublicKey);
}
