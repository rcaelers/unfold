// Copyright (C) 2025 Rob Caelers <rob.caelers@gmail.com>
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

#include "sigstore/SigstoreVerifier.hh"
#include "sigstore/SigstoreErrors.hh"
#include "HttpClientMock.hh"

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

using namespace unfold::sigstore;
using namespace testing;

struct GlobalSigStoreTest : public ::testing::Environment
{
  GlobalSigStoreTest() = default;
  ~GlobalSigStoreTest() override = default;

  GlobalSigStoreTest(const GlobalSigStoreTest &) = delete;
  GlobalSigStoreTest &operator=(const GlobalSigStoreTest &) = delete;
  GlobalSigStoreTest(GlobalSigStoreTest &&) = delete;
  GlobalSigStoreTest &operator=(GlobalSigStoreTest &&) = delete;

  void SetUp() override
  {
    const auto *log_file = "unfold-test-sigstore.log";

    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file, false);
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    auto logger{std::make_shared<spdlog::logger>("unfold", std::initializer_list<spdlog::sink_ptr>{file_sink, console_sink})};
    logger->flush_on(spdlog::level::critical);
    logger->set_level(spdlog::level::debug);
    spdlog::set_default_logger(logger);

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

::testing::Environment *const global_env = ::testing::AddGlobalTestEnvironment(new GlobalSigStoreTest);

class SigstoreTest : public ::testing::Test
{
public:
  std::shared_ptr<unfold::http::IHttpClient> mock_http_client_;

protected:
  void SetUp() override
  {
    // Create a mock HttpClient
    mock_http_client_ = std::make_shared<HttpClientMock>();
  }

  void TearDown() override
  {
  }
};

TEST_F(SigstoreTest, VerifyInvalidBundle)
{
  // TODO: Fix async testing - this test needs to be updated to handle coroutines properly
  // SigstoreVerifier verifier(mock_http_client_);

  // Try to verify with invalid bundle
  // std::string invalid_bundle = R"({"invalid": "bundle"})";
  // std::string content = "Hello, World!";

  // auto verify_result = verifier.verify(content, invalid_bundle);
  // EXPECT_TRUE(verify_result.has_error());
}

TEST_F(SigstoreTest, SetInvalidPublicKey)
{
  SigstoreVerifier verifier(mock_http_client_);

  std::string invalid_key = "invalid public key";
  auto result = verifier.set_rekor_public_key(invalid_key);
  EXPECT_TRUE(result.has_error());
  EXPECT_EQ(result.error().value(), static_cast<int>(SigstoreError::InvalidCertificate));
}

TEST_F(SigstoreTest, ParseNewBundleFormat)
{
  // Test with a valid-looking bundle structure (though verification will fail)
  SigstoreVerifier verifier(mock_http_client_);

  std::string new_bundle_format = R"({
    "base64Signature": "MEUCID1iKgR4BeZTz+zoHqocEDZ/zWgFD2P3dUZJ0AuQqJxmAiEA9g/4S9fhwuh4VPQ8eRhkO2x8SN2X2J8BjfOSxnFrDzw=",
    "cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMwekNDQWxxZ0F3SUJBZ0lVWUZQRk11MGNueWZPSHBNNm1SZUdtWVh2MGEwd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpVd056QTVNVGd3TWpRMldoY05NalV3TnpBNU1UZ3hNalEyV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVYcXNHWVJaMUo4SHptclhqMVlRZ0ltQ2I5SUQ5U0xPd01QZjQKM1pORXFaOVg3aVMxSFd2WjQ2MThoNVFqSk5qbjcxMHFjWmFRWTVlTXVOamV2cFc5V2FPQ0FYa3dnZ0YxTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVV2RnlwClZxbDBrL25CRk1xY3Q4UHFxbFhlT2NFd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0l3WURWUjBSQVFIL0JCa3dGNEVWY205aUxtTmhaV3hsY25OQVoyMWhhV3d1WTI5dE1Dd0dDaXNHQVFRQgpnNzh3QVFFRUhtaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOXNiMmRwYmk5dllYVjBhREF1QmdvckJnRUVBWU8vCk1BRUlCQ0FNSG1oMGRIQnpPaTh2WjJsMGFIVmlMbU52YlM5c2IyZHBiaTl2WVhWMGFEQ0JpZ1lLS3dZQkJBSFcKZVFJRUFnUjhCSG9BZUFCMkFOMDlNR3JHeHhFeVl4a2VISmxuTndLaVNsNjQzanl0LzRlS2NvQXZLZTZPQUFBQgpsL0JhdHVFQUFBUURBRWN3UlFJZ0hmVFdxRXROaUtKZElQM0hseDNqZnBUbEU1RUtMcnpRYURyOFhOb2QvbDhDCklRQ080MUxyeTBFMFJnQ2sxMk5qelhMZ0kzZlg5MElNYmpZT0NpN3FwSjFwb2pBS0JnZ3Foa2pPUFFRREF3Tm4KQURCa0FqQkR4dEN6TUJpOXVHYVlmbEZrbGtIYjlnYUkxQWVwU3k5RHhSdUllZ2RzTG52dEhOZDNyTHdiZlBxSgpaT3c0QjRRQ01CNDFvQytPMWhPMTVxaTFMdFFWQm16a1hMdFdJeTZ5b3VIUjFrc0pDTVk5aW1OV1ZlK3BVSlFNCi80bHh2ajcvcWc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
    "rekorBundle": {
      "logEntry": {
        "logIndex": "123456",
        "logID": "rekor.sigstore.dev",
        "body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJhYzY1YzIyOWFkYTZjNGUyYjY5YTY4MjI0YzQzYjNhZDMxNzQyZGQxNzMwZTY1YmQ5M2I2ZmU3MTc0Yzk3MjQxIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJUURGVDBYdHNaYjNuWEhLMjJMaDdGM2NLZGR6Q0FGdTh5YWJEU3ZSUmxrcThBSWdOaWduVVhmZ05XNGt2N3E2RXFTNGJSSkxwUVByWWMxOG9jVW1yaW56ckpFPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTXdla05EUVd4eFowRjNTVUpCWjBsVldVWlFSazExTUdOdWVXWlBTSEJOTm0xU1pVZHRXVmgyTUdGd0F3bFVha1pKZW1wd1FWSjNiWGN0TnpGV1RFRDJLMDJUU2pOa1VGTm5KbUJITUZKUkNnWkVUVUJsRUZsemFXZHpkRzl5WlM1cFptNVdwUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpVd056QTVNVGd3TWpRMldoY05NalV3TnpBNU1UZ3hNalEyV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVYcXNHWVJaMUo4SHptclhqMVlRZ0ltQ2I5SUQ5U0xPd01QZjQKM1pORXFaOVg3aVMxSFd2WjQ2MThoNVFqSk5qbjcxMHFjWmFRWTVlTXVOamV2cFc5V2FPQ0FYa3dnZ0YxTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVV2RnlwClZxbDBrL25CRk1xY3Q4UHFxbFhlT2NFd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0l3WURWUjBSQVFIL0JCa3dGNEVWY205aUxtTmhaV3hsY25OQVoyMWhhV3d1WTI5dE1Dd0dDaXNHQVFRQgpnNzh3QVFFRUhtaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOXNiMmRwYmk5dllYVjBhREF1QmdvckJnRUVBWU8vCk1BRUlCQ0FNSG1oMGRIQnpPaTh2WjJsMGFIVmlMbU52YlM5c2IyZHBiaTl2WVhWMGFEQ0JpZ1lLS3dZQkJBSFcKZVFJRUFnUjhCSG9BZUFCMkFOMDlNR3JHeHhFeVl4a2VISmxuTndLaVNsNjQzanl0LzRlS2NvQXZLZTZPQUFBQgpsL0JhdHVFQUFBUURBRWN3UlFJZ0hmVFdxRXROaUtKZElQM0hseDNqZnBUbEU1RUtMcnpRYURyOFhOb2QvbDhDCklRQ080MUxyeTBFMFJnQ2sxMk5qelhMZ0kzZlg5MElNYmpZT0NpN3FwSjFwb2pBS0JnZ3Foa2pPUFFRREF3Tm4KQURCa0FqQkR4dEN6TUJpOXVHYVlmbEZrbGtIYjlnYUkxQWVwU3k5RHhSdUllZ2RzTG52dEhOZDNyTHdiZlBxSgpaT3c0QjRRQ01CNDFvQytPMWhPMTVxaTFMdFFWQm16a1hMdFdJeTZ5b3VIUjFrc0pDTVk5aW1OV1ZlK3BVSlFNCi80bHh2ajcvcWc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tQ2c9PSJ9fX19"
      }
    }
  })";

  std::string content = "test content";
  // auto result = run_coro(verifier.verify(content, new_bundle_format));

  // This will fail because the signature doesn't match the content, but tests parsing
  // EXPECT_TRUE(result.has_error());
}
