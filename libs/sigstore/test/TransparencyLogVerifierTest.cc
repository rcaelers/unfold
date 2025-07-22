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

#include <boost/json/serialize.hpp>
#include <boost/json/serializer.hpp>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <spdlog/logger.h>
#include <vector>
#include <chrono>
#include <optional>
#include <fstream>
#include <regex>
#include <string>

#include "TransparencyLogVerifier.hh"
#include "SigstoreStandardBundle.hh"
#include "Certificate.hh"
#include "utils/Base64.hh"
#include "TransparencyLogEntry.hh"
#include "SigstoreBundleBase.hh"

using namespace unfold::sigstore;

enum class TestDataFormat
{
  StandardBundle, // Complete Sigstore bundle with mediaType and verificationMaterial
  TransparencyLog // Transparency log API response format
};

struct TestBundleData
{
  std::string bundle_filename;
  std::string description;
  TestDataFormat format_type;
};

void
PrintTo(const TestBundleData &data, std::ostream *os)
{
  *os << "TestBundleData{bundle_filename=\"" << data.bundle_filename << "\", description=\"" << data.description
      << "\", format_type=" << static_cast<int>(data.format_type) << "}";
}

class TransparencyLogVerifierTest : public ::testing::TestWithParam<TestBundleData>
{
protected:
  void SetUp() override
  {
    verifier_ = std::make_unique<TransparencyLogVerifier>();
  }

  std::unique_ptr<Certificate> create_test_certificate()
  {
    std::string cert_base64 =
      "MIIC1TCCAlqgAwIBAgIUVyf2i/kSHHcUvZCiAGB2q+B39eMwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNzEwMTgwNjA2WhcNMjUwNzEwMTgxNjA2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIZLdcmiYUHnyCmbyDODkt0TUS3hnUfD6hLLqWYKR0X48eL6aR7UsehluA0gYtNKypbJOLJdY/P94uKGZ1lvqbaOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUWg8/Map8qWkIDlker4y1lyi8mEswHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABl/WEIfUAAAQDAEcwRQIhANStMu8Ou4C2PHLIO6l5S0HZhdKVmIE9bTSobiOkjQBIAiATIbUPI8/xWAdKw3qTYvynwqTN1Ic4GSQZiMrnSy9P/jAKBggqhkjOPQQDAwNpADBmAjEAyLhTOg6lSrmMjX1HmcnbC/LSNJMBwugR3Vg1T5b81V5Ky3wLfDFM7pi4xRht4MONAjEAwEtFcEY1XfinR+mknwGt653egNEnUJmRK48UbplR9KmQ6/9iISMk50sX1JI2tlxP";

    try
      {
        std::string cert_der_str = unfold::utils::Base64::decode(cert_base64);
        std::vector<uint8_t> cert_der(cert_der_str.begin(), cert_der_str.end());

        auto cert_result = Certificate::from_der(cert_der);
        if (cert_result)
          {
            return std::make_unique<Certificate>(std::move(cert_result.value()));
          }
      }
    catch (const std::exception &e)
      {
        ADD_FAILURE() << "Failed to create test certificate: " << e.what();
        return nullptr;
      }
    return nullptr;
  }

  class MockSigstoreBundle : public SigstoreBundleBase
  {
  public:
    MOCK_METHOD(std::string, get_signature, (), (const, override));
    MOCK_METHOD(std::shared_ptr<Certificate>, get_certificate, (), (const, override));
    MOCK_METHOD(std::optional<std::string>, get_message_digest, (), (const, override));
    MOCK_METHOD(std::optional<std::string>, get_algorithm, (), (const, override));
    MOCK_METHOD(int64_t, get_log_index, (), (const, override));

    std::shared_ptr<Certificate> test_certificate_;
  };

  std::shared_ptr<MockSigstoreBundle> create_test_bundle()
  {
    auto certificate = create_test_certificate();
    auto mock_bundle = std::make_shared<MockSigstoreBundle>();

    mock_bundle->test_certificate_ = std::shared_ptr<Certificate>(std::move(certificate));

    EXPECT_CALL(*mock_bundle, get_signature())
      .WillRepeatedly(
        ::testing::Return("MEYCIQD72gqPTp1QtkOfZ49+cQNWFKjs/fV7FXmpgd4XHOiFCwIhAMd5/Dv80ZgkLbiINDG/7LjjciDvY4UcX9+3FXa4jdp6"));
    EXPECT_CALL(*mock_bundle, get_certificate()).WillRepeatedly(::testing::Return(mock_bundle->test_certificate_));
    EXPECT_CALL(*mock_bundle, get_message_digest())
      .WillRepeatedly(::testing::Return(std::optional<std::string>("ZLWzeHWZ5tm+0MjeKNfd8MMAxA/A4qEKkNf7kOQayyA=")));
    EXPECT_CALL(*mock_bundle, get_algorithm()).WillRepeatedly(::testing::Return(std::optional<std::string>("sha256")));
    EXPECT_CALL(*mock_bundle, get_log_index()).WillRepeatedly(::testing::Return(0));

    return mock_bundle;
  }
  outcome::std_result<std::pair<TransparencyLogEntry, std::shared_ptr<SigstoreBundleBase>>> load_current_test_log(
    std::function<void(boost::json::value &json_val)> patch = [](boost::json::value &json_val) {})
  {
    const auto &test_data = GetParam();

    switch (test_data.format_type)
      {
      case TestDataFormat::StandardBundle:
        return load_standard_bundle(test_data.bundle_filename, patch);

      case TestDataFormat::TransparencyLog:
        return load_transparency_log(test_data.bundle_filename, patch);

      default:
        ADD_FAILURE() << "Unknown test data format type";
        return outcome::failure(std::make_error_code(std::errc::invalid_argument));
      }
  }

  outcome::std_result<std::pair<TransparencyLogEntry, std::shared_ptr<SigstoreBundleBase>>> load_standard_bundle(
    std::string file_path,
    std::function<void(boost::json::value &json_val)> patch = [](boost::json::value &json_val) {})
  {
    if (file_path.empty())
      {
        ADD_FAILURE() << "Failed to open bundle empty file";
        return outcome::failure(std::make_error_code(std::errc::invalid_argument));
      }

    std::ifstream bundle_file(file_path);
    if (!bundle_file.is_open())
      {
        ADD_FAILURE() << "Failed to open bundle file: " << file_path;
        return outcome::failure(std::make_error_code(std::errc::no_such_file_or_directory));
      }

    std::string bundle_json_str((std::istreambuf_iterator<char>(bundle_file)), std::istreambuf_iterator<char>());
    bundle_file.close();

    try
      {
        boost::json::value json_val = boost::json::parse(bundle_json_str);

        if (json_val.is_null())
          {
            ADD_FAILURE() << "Failed to parse JSON from bundle file: " << file_path;
            return outcome::failure(std::make_error_code(std::errc::invalid_argument));
          }
        try
          {
            patch(json_val);
          }
        catch (const std::exception &e)
          {
            ADD_FAILURE() << "Failed to apply patch to JSON: " << e.what();
            return outcome::failure(std::make_error_code(std::errc::invalid_argument));
          }
        auto bundle = SigstoreStandardBundle::from_json(json_val);
        if (!bundle)
          {
            return outcome::failure(bundle.error());
          }
        auto log_entries = bundle.value()->get_transparency_log_entries();
        if (log_entries.empty())
          {
            return outcome::failure(std::make_error_code(std::errc::invalid_argument));
          }

        return outcome::success(std::make_pair(std::move(log_entries[0]), std::move(bundle.value())));
      }
    catch (const std::exception &e)
      {
        ADD_FAILURE() << "Failed to load log from file: " << e.what();
        return outcome::failure(std::make_error_code(std::errc::invalid_argument));
      }
  }

  outcome::std_result<std::pair<TransparencyLogEntry, std::shared_ptr<SigstoreBundleBase>>> load_transparency_log(
    std::string file_path,
    std::function<void(boost::json::value &json_val)> patch)
  {
    if (file_path.empty())
      {
        ADD_FAILURE() << "Failed to open transparency log file: empty path";
        return outcome::failure(std::make_error_code(std::errc::invalid_argument));
      }

    std::ifstream tlog_file(file_path);
    if (!tlog_file.is_open())
      {
        ADD_FAILURE() << "Failed to open transparency log file: " << file_path;
        return outcome::failure(std::make_error_code(std::errc::no_such_file_or_directory));
      }

    std::string tlog_json_str((std::istreambuf_iterator<char>(tlog_file)), std::istreambuf_iterator<char>());
    tlog_file.close();

    try
      {
        boost::json::value json_val = boost::json::parse(tlog_json_str);

        if (json_val.is_null() || !json_val.is_object())
          {
            ADD_FAILURE() << "Failed to parse JSON from transparency log file: " << file_path;
            return outcome::failure(std::make_error_code(std::errc::invalid_argument));
          }

        try
          {
            patch(json_val);
          }
        catch (const std::exception &e)
          {
            ADD_FAILURE() << "Failed to apply patch to transparency log JSON: " << e.what();
            return outcome::failure(std::make_error_code(std::errc::invalid_argument));
          }

        const auto &root_obj = json_val.as_object();
        if (root_obj.empty())
          {
            return outcome::failure(std::make_error_code(std::errc::invalid_argument));
          }

        TransparencyLogEntryParser parser;
        auto entry_result = parser.parse_api_response(json_val);
        if (!entry_result)
          {
            return outcome::failure(entry_result.error());
          }

        auto mock_bundle = create_test_bundle();
        return std::make_pair(entry_result.value(), mock_bundle);
      }
    catch (const std::exception &e)
      {
        ADD_FAILURE() << "Exception parsing transparency log JSON: " << e.what();
        return outcome::failure(std::make_error_code(std::errc::invalid_argument));
      }
  }

  void apply_json_patch(boost::json::value &json_val,
                        const std::string &bundle_path,
                        const std::string &api_path,
                        std::function<void(boost::json::object &)> patch_func) const
  {
    const auto &test_data = GetParam();
    std::string target_path;

    if (test_data.format_type == TestDataFormat::TransparencyLog)
      {
        const auto &root_obj = json_val.as_object();
        if (root_obj.empty())
          {
            throw std::runtime_error("Empty transparency log object");
          }

        auto uuid_key = std::string(root_obj.begin()->key());
        target_path = api_path;

        size_t pos = target_path.find("{UUID}");
        if (pos != std::string::npos)
          {
            target_path.replace(pos, 6, uuid_key); // 6 is length of "{UUID}"
          }
      }
    else
      {
        target_path = bundle_path;
      }

    try
      {
        auto &target_obj = json_val.at_pointer(target_path).as_object();
        patch_func(target_obj);
      }
    catch (const std::exception &e)
      {
        throw std::runtime_error("Failed to apply patch at path: " + target_path + " - " + e.what());
      }
  }

  std::unique_ptr<TransparencyLogVerifier> verifier_;
};

// =============================================================================
//
// =============================================================================

TEST_P(TransparencyLogVerifierTest, ValidateValidLog)
{
  auto log = load_current_test_log();
  ASSERT_FALSE(log.has_error()) << "Failed to load test data for " << GetParam().description;
  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_value()) << "Failed to verify transparency log for " << GetParam().description << ": "
                                  << result.error().message();
  ASSERT_TRUE(result) << "Failed to verify transparency log for " << GetParam().description << ": " << result.error().message();
}

TEST_P(TransparencyLogVerifierTest, ValidateValidBundle)
{
  auto log = load_current_test_log();
  ASSERT_FALSE(log.has_error()) << "Failed to load test data for " << GetParam().description;
  auto [log_entry, bundle] = log.value();

  auto result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_value()) << "Failed to verify bundle consistency for " << GetParam().description << ": "
                                  << result.error().message();
  ASSERT_TRUE(result) << "Failed to verify bundle consistency for " << GetParam().description << ": " << result.error().message();
}

// =============================================================================
//
// =============================================================================

TEST_P(TransparencyLogVerifierTest, ValidateLog_NoInclusionProof)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}/verification", [](boost::json::object &obj) {
      obj.erase(obj.find("inclusionProof"));
    });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofWrongType)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}/verification", [](boost::json::object &obj) {
      obj.erase(obj.find("inclusionProof"));
      obj["inclusionProof"] = "invalid-type";
    });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofCheckPoint)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.erase(obj.find("checkpoint")); });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofCanonicalizedBody)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}", [](boost::json::object &obj) {
      auto *it = obj.find("canonicalizedBody");
      if (it != obj.end())
        {
          obj.erase(it);
        }
      else
        {
          auto *body_it = obj.find("body");
          if (body_it != obj.end())
            {
              obj.erase(body_it);
            }
        }
    });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCanonicalizedBody)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}", [](boost::json::object &obj) {
      auto *it = obj.find("canonicalizedBody");
      if (it != obj.end())
        {
          it->value() = "invalid-base64";
        }
      else
        {
          auto *body_it = obj.find("body");
          if (body_it != obj.end())
            {
              body_it->value() = "invalid-base64";
            }
        }
    });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofLogIndex)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.erase(obj.find("logIndex")); });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofLogIndex1)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.find("logIndex")->value() = "0"; });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofLogIndex2)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.find("logIndex")->value() = "999999999"; });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofLogIndex3)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.find("logIndex")->value() = "foo"; });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofTreeSize)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.erase(obj.find("treeSize")); });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofTreeSize1)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.find("treeSize")->value() = "0"; });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofTreeSize2)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.find("treeSize")->value() = "999999999"; });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofTreeSize3)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.find("treeSize")->value() = "foo"; });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofRootHash)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.erase(obj.find("rootHash")); });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofRootHash)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.find("rootHash")->value() = "foo"; });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofHashes)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.erase(obj.find("hashes")); });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofHashes)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) {
                       auto &hashes = obj.find("hashes")->value().as_array();
                       hashes[0] = "invalid-hash";
                     });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_EmptyInclusionProofHashes)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) { obj.find("hashes")->value() = boost::json::array{}; });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpoint1)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) {
                       auto *checkpoint_it = obj.find("checkpoint");
                       if (checkpoint_it != obj.end())
                         {
                           if (checkpoint_it->value().is_object())
                             {
                               auto &checkpoint_obj = checkpoint_it->value().as_object();
                               checkpoint_obj.find("envelope")->value() = "invalid-checkpoint-envelope";
                             }
                           else
                             {
                               checkpoint_it->value() = "invalid-checkpoint-envelope";
                             }
                         }
                     });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpoint2)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionProof",
                     "/{UUID}/verification/inclusionProof",
                     [](boost::json::object &obj) {
                       auto *checkpoint_it = obj.find("checkpoint");
                       if (checkpoint_it != obj.end())
                         {
                           if (checkpoint_it->value().is_object())
                             {
                               auto &checkpoint_obj = checkpoint_it->value().as_object();
                               checkpoint_obj.find("envelope")->value() = "";
                             }
                           else
                             {
                               checkpoint_it->value() = "";
                             }
                         }
                     });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointInconsistentTreeSize)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(
      json_val,
      "/verificationMaterial/tlogEntries/0/inclusionProof",
      "/{UUID}/verification/inclusionProof",
      [&](boost::json::object &obj) {
        auto *checkpoint_it = obj.find("checkpoint");
        if (checkpoint_it != obj.end())
          {
            if (checkpoint_it->value().is_object())
              {
                const auto *envelope_value =
                  "rekor.sigstore.dev - 1193050959916656506\n148680320\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=\n";
                auto &checkpoint_obj = checkpoint_it->value().as_object();
                checkpoint_obj.find("envelope")->value() = envelope_value;
              }
            else
              {
                const auto *envelope_value =
                  "rekor.sigstore.dev - 1193050959916656506\n15116574\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n\n— rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC\n";
                checkpoint_it->value() = envelope_value;
              }
          }
      });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointTreeSizeWrongType)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(
      json_val,
      "/verificationMaterial/tlogEntries/0/inclusionProof",
      "/{UUID}/verification/inclusionProof",
      [&](boost::json::object &obj) {
        auto *checkpoint_it = obj.find("checkpoint");
        if (checkpoint_it != obj.end())
          {
            if (checkpoint_it->value().is_object())
              {
                const auto *envelope_value =
                  "rekor.sigstore.dev - 1193050959916656506\nx148680320\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=\n";
                auto &checkpoint_obj = checkpoint_it->value().as_object();
                checkpoint_obj.find("envelope")->value() = envelope_value;
              }
            else
              {
                const auto *envelope_value =
                  "rekor.sigstore.dev - 1193050959916656506\nx15116564\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n\n— rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC\n";
                checkpoint_it->value() = envelope_value;
              }
          }
      });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointNoBody)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(
      json_val,
      "/verificationMaterial/tlogEntries/0/inclusionProof",
      "/{UUID}/verification/inclusionProof",
      [&](boost::json::object &obj) {
        auto *checkpoint_it = obj.find("checkpoint");
        if (checkpoint_it != obj.end())
          {
            if (checkpoint_it->value().is_object())
              {
                const auto *envelope_value =
                  "\n\nrekor.sigstore.dev - 1193050959916656506\n148680319\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=\n";
                auto &checkpoint_obj = checkpoint_it->value().as_object();
                checkpoint_obj.find("envelope")->value() = envelope_value;
              }
            else
              {
                const auto *envelope_value =
                  "\n\nrekor.sigstore.dev - 1193050959916656506\n15116564\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n— rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC\n";
                checkpoint_it->value() = envelope_value;
              }
          }
      });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointNoSeparator)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(
      json_val,
      "/verificationMaterial/tlogEntries/0/inclusionProof",
      "/{UUID}/verification/inclusionProof",
      [](boost::json::object &obj) {
        auto *checkpoint_it = obj.find("checkpoint");
        if (checkpoint_it != obj.end())
          {
            if (checkpoint_it->value().is_object())
              {
                const auto *envelope_value =
                  "rekor.sigstore.dev - 1193050959916656506\n148680319\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=\n";
                auto &checkpoint_obj = checkpoint_it->value().as_object();
                checkpoint_obj.find("envelope")->value() = envelope_value;
              }
            else
              {
                const auto *envelope_value =
                  "rekor.sigstore.dev - 1193050959916656506\n15116564\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n— rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC\n";
                checkpoint_it->value() = envelope_value;
              }
          }
      });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointNoNewLine)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(
      json_val,
      "/verificationMaterial/tlogEntries/0/inclusionProof",
      "/{UUID}/verification/inclusionProof",
      [](boost::json::object &obj) {
        auto *checkpoint_it = obj.find("checkpoint");
        if (checkpoint_it != obj.end())
          {
            if (checkpoint_it->value().is_object())
              {
                const auto *envelope_value =
                  "rekor.sigstore.dev - 1193050959916656506\n148680319\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=";
                auto &checkpoint_obj = checkpoint_it->value().as_object();
                checkpoint_obj.find("envelope")->value() = envelope_value;
              }
            else
              {
                const auto *envelope_value =
                  "rekor.sigstore.dev - 1193050959916656506\n151165654\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n\n— rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC";
                checkpoint_it->value() = envelope_value;
              }
          }
      });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointWrongSignature)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(
      json_val,
      "/verificationMaterial/tlogEntries/0/inclusionProof",
      "/{UUID}/verification/inclusionProof",
      [&](boost::json::object &obj) {
        auto *checkpoint_it = obj.find("checkpoint");
        if (checkpoint_it != obj.end())
          {
            if (checkpoint_it->value().is_object())
              {
                const auto *envelope_value =
                  "rekor.sigstore.dev - 1193050959916656506\n148680319\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n\nx rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=";
                auto &checkpoint_obj = checkpoint_it->value().as_object();
                checkpoint_obj.find("envelope")->value() = envelope_value;
              }
            else
              {
                const auto *envelope_value =
                  "rekor.sigstore.dev - 1193050959916656506\n151165654\nmQzjnEcka/8RktFYpvWYHha4kQcfzNVgTAMmg4OghL8=\n\nx rekor.sigstore.dev wNI9ajBFAiEA/3AFziktWhi/OYoqavWWSpVZC/EBTw2nZPltb200J1oCIG4JmkmTXrItmU4bUeJiYjTWAzwIvTO0ISB7OrbIadgC";
                checkpoint_it->value() = envelope_value;
              }
          }
      });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

// =============================================================================
// Top-level mediaType Tests
// =============================================================================

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoMediaType)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj.erase(obj.find("mediaType"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidMediaType)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj.find("mediaType")->value() = "invalid/media-type";
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());
  // TODO: mediaType is ignore if present

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

// =============================================================================
// Certificate Tests
// =============================================================================

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoCertificate)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial").as_object();
    obj.erase(obj.find("certificate"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoCertificateRawBytes)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/certificate").as_object();
    obj.erase(obj.find("rawBytes"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidCertificateRawBytes)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/certificate").as_object();
    obj.find("rawBytes")->value() = "invalid-certificate-data";
  });
  ASSERT_TRUE(log.has_error());
}

// =============================================================================
// tlogEntries Tests
// =============================================================================

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoTlogEntries)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial").as_object();
    obj.erase(obj.find("tlogEntries"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_EmptyTlogEntries)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial").as_object();
    obj.find("tlogEntries")->value() = boost::json::array{};
  });
  ASSERT_TRUE(log.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_NoTlogEntryLogIndex)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}", [](boost::json::object &obj) {
      obj.erase(obj.find("logIndex"));
    });
  });
  ASSERT_TRUE(log.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidTlogEntryLogIndex)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}", [](boost::json::object &obj) {
      obj.find("logIndex")->value() = "invalid-log-index";
    });
  });
  ASSERT_TRUE(log.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_NoLogId)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}", [](boost::json::object &obj) {
      auto *it = obj.find("logId");
      if (it != obj.end())
        {
          obj.erase(it);
        }
      else
        {
          auto *it_api = obj.find("logID");
          if (it_api != obj.end())
            {
              obj.erase(it_api);
            }
        }
    });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_LogIdWrongType)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}", [](boost::json::object &obj) {
      auto *it = obj.find("logId");
      if (it != obj.end())
        {
          obj.erase(it);
          obj["logId"] = "invalid-log-id-type";
        }
      else
        {
          auto *it_api = obj.find("logID");
          if (it_api != obj.end())
            {
              obj.erase(it_api);
              obj["logID"] = "invalid-log-id-type";
            }
        }
    });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoLogIdKeyId)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/tlogEntries/0/logId").as_object();
    obj.erase(obj.find("keyId"));
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidLogIdKeyId)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/tlogEntries/0/logId").as_object();
    obj.find("keyId")->value() = "invalid-key-id";
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoKindVersion)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    obj.erase(obj.find("kindVersion"));
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidKindVersionWrongType)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    o.erase(o.find("kindVersion"));
    o["kindVersion"] = "invalid-kind-version-type";
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoKindVersionKind)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.erase(o.find("kind"));
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidKindVersionKind)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.find("kind")->value() = "invalid-kind";
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());
  // TODO: check

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoKindVersionVersion)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.erase(o.find("version"));
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());
  // TODO: check

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidKindVersionVersion)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.find("version")->value() = "invalid-version";
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());
  // TODO: check

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_NoIntegratedTime)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}", [](boost::json::object &obj) {
      obj.erase(obj.find("integratedTime"));
    });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidIntegratedTime)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}", [](boost::json::object &obj) {
      obj.find("integratedTime")->value() = "invalid-time";
    });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_IntegratedTimeOutOfRange)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}", [](boost::json::object &obj) {
      obj.find("integratedTime")->value() = "1752174767";
    });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_IntegratedTimeFuture)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", "/{UUID}", [](boost::json::object &obj) {
      auto current_time = std::chrono::system_clock::now();
      auto out_of_range_time = std::chrono::duration_cast<std::chrono::seconds>(current_time.time_since_epoch()).count()
                               + 1000000;
      obj.find("integratedTime")->value() = std::to_string(out_of_range_time);
    });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoInclusionPromise)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    o.erase(o.find("inclusionPromise"));
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InclusionPromiseWrongType)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    o.erase(o.find("inclusionPromise"));
    o["inclusionPromise"] = "invalid-inclusion-promise-type";
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_NoInclusionPromiseSignedEntryTimestamp)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionPromise",
                     "/{UUID}/verification",
                     [](boost::json::object &obj) { obj.erase(obj.find("signedEntryTimestamp")); });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_P(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionPromiseSignedEntryTimestamp)
{
  auto log = load_current_test_log([this](boost::json::value &json_val) {
    apply_json_patch(json_val,
                     "/verificationMaterial/tlogEntries/0/inclusionPromise",
                     "/{UUID}/verification",
                     [](boost::json::object &obj) {
                       spdlog::debug("json = {}", boost::json::serialize(obj));
                       obj.find("signedEntryTimestamp")->value() = "invalid-timestamp";
                     });
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

// =============================================================================
// messageSignature Tests
// =============================================================================

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoMessageSignature)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.as_object();
    o.erase(o.find("messageSignature"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoMessageDigest)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature").as_object();
    o.erase(o.find("messageDigest"));
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());
  // TODO: check

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoMessageDigestAlgorithm)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.erase(o.find("algorithm"));
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());
  // TODO: check

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidMessageDigestAlgorithm)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.find("algorithm")->value() = "INVALID_ALGO";
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());
  // TODO: check

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoMessageDigestDigest)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.erase(o.find("digest"));
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());
  // TODO: check

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidMessageDigestDigest)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.find("digest")->value() = "invalid-digest";
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());
  // TODO: check

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoMessageSignatureSignature)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature").as_object();
    o.erase(o.find("signature"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidMessageSignatureSignature)
{
  auto log = load_standard_bundle("appcast-sigstore.xml.sigstore.new.bundle", [](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature").as_object();
    o.find("signature")->value() = "invalid-signature";
  });

  auto [log_entry, bundle] = log.value();
  std::shared_ptr<const Certificate> cert = bundle->get_certificate();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());
  // TODO: check

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

// =============================================================================
// Parameterized Test Instantiation
// =============================================================================

INSTANTIATE_TEST_SUITE_P(
  MultipleDataSources,
  TransparencyLogVerifierTest,
  ::testing::Values(
    TestBundleData{"appcast-sigstore.xml.sigstore.new.bundle", "New Bundle Format", TestDataFormat::StandardBundle},
    TestBundleData{"tlog.json", "Transparency Log JSON Format", TestDataFormat::TransparencyLog}),
  [](const ::testing::TestParamInfo<TestBundleData> &info) {
    return info.param.description.empty() ? "UnknownFormat"
                                          : std::regex_replace(info.param.description, std::regex("[^a-zA-Z0-9]"), "_");
  });
