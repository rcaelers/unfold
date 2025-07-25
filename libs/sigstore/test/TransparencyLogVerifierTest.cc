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
#include <boost/outcome/success_failure.hpp>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <spdlog/logger.h>
#include <tuple>
#include <vector>
#include <chrono>
#include <optional>
#include <fstream>
#include <regex>
#include <string>

#include "TransparencyLogVerifier.hh"
#include "BundleLoader.hh"
#include "Certificate.hh"
#include "sigstore/SigstoreErrors.hh"
#include "utils/Base64.hh"

#include "sigstore_rekor.pb.h"

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

class TransparencyLogVerifierTest : public ::testing::Test
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

  outcome::std_result<std::tuple<dev::sigstore::rekor::v1::TransparencyLogEntry, dev::sigstore::bundle::v1::Bundle, Certificate>>
  load_standard_bundle(std::function<void(boost::json::value &json_val)> patch = [](boost::json::value &json_val) {})
  {
    std::string file_path = "appcast-sigstore.xml.sigstore.new.bundle";
    if (file_path.empty())
      {
        ADD_FAILURE() << "Failed to open bundle empty file";
        return SigstoreError::InvalidBundle;
      }

    std::ifstream bundle_file(file_path);
    if (!bundle_file.is_open())
      {
        ADD_FAILURE() << "Failed to open bundle file: " << file_path;
        return SigstoreError::InvalidBundle;
      }

    std::string bundle_json_str((std::istreambuf_iterator<char>(bundle_file)), std::istreambuf_iterator<char>());
    bundle_file.close();

    try
      {
        boost::json::value json_val = boost::json::parse(bundle_json_str);

        if (json_val.is_null())
          {
            ADD_FAILURE() << "Failed to parse JSON from bundle file: " << file_path;
            return SigstoreError::InvalidBundle;
          }
        try
          {
            patch(json_val);
          }
        catch (const std::exception &e)
          {
            ADD_FAILURE() << "Failed to apply patch to JSON: " << e.what();
            return SigstoreError::InvalidBundle;
          }
        spdlog::debug("Loaded bundle JSON: {}", boost::json::serialize(json_val));
        SigstoreBundleLoader loader;
        auto bundle_result = loader.load_from_json(boost::json::serialize(json_val));
        if (!bundle_result)
          {
            return SigstoreError::InvalidBundle;
          }

        auto &bundle = bundle_result.value();
        auto log_entries = bundle.verification_material().tlog_entries();
        if (log_entries.empty())
          {
            return SigstoreError::InvalidBundle;
          }
        auto cert_result = Certificate::from_cert(bundle.verification_material().certificate());
        if (!cert_result.has_value())
          {
            return SigstoreError::InvalidBundle;
          }
        auto cert = std::move(cert_result.value());
        return {std::move(log_entries[0]), std::move(bundle), std::move(cert)};
      }
    catch (const std::exception &e)
      {
        return SigstoreError::InvalidBundle;
      }
  }

  void apply_json_patch(boost::json::value &json_val, const std::string &bundle_patch, std::function<void(boost::json::object &)> patch_func) const
  {
    try
      {
        auto &target_obj = json_val.at_pointer(bundle_patch).as_object();
        patch_func(target_obj);
      }
    catch (const std::exception &e)
      {
        spdlog::error("Failed to apply patch at path {}: {}", bundle_patch, e.what());
        throw std::runtime_error("Failed to apply patch at path: " + bundle_patch + " - " + e.what());
      }
  }

  std::unique_ptr<TransparencyLogVerifier> verifier_;
};

// =============================================================================
// Valid JSON
// =============================================================================

TEST_F(TransparencyLogVerifierTest, ValidateValidLog)
{
  auto log = load_standard_bundle();
  ASSERT_FALSE(log.has_error()) << "Failed to load test data";
  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_value()) << "Failed to verify transparency log: " << result.error().message();
  ASSERT_TRUE(result) << "Failed to verify transparency log: " << result.error().message();
}

TEST_F(TransparencyLogVerifierTest, ValidateValidBundle)
{
  auto log = load_standard_bundle();
  ASSERT_FALSE(log.has_error()) << "Failed to load test data";
  ;
  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_value()) << "Failed to verify bundle consistency: " << result.error().message();
  ASSERT_TRUE(result) << "Failed to verify bundle consistency: " << result.error().message();
}

// =============================================================================
// Inalid JSON
// =============================================================================

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoInclusionProof)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) { obj.erase(obj.find("inclusionProof")); });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofWrongType)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      obj.erase(obj.find("inclusionProof"));
      obj["inclusionProof"] = "invalid-type";
    });
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofCheckPoint)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.erase(obj.find("checkpoint"));
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofCanonicalizedBody)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
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

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCanonicalizedBody)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
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

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofLogIndex)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.erase(obj.find("logIndex"));
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofLogIndex1)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      obj.find("logIndex")->value() = "0";
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofLogIndex2)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      obj.find("logIndex")->value() = "999999999";
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofLogIndex3)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.find("logIndex")->value() = "foo";
    });
  });
  ASSERT_TRUE(log.has_error());
  // auto &[log_entry, bundle, cert] = log.value();

  // auto result = verifier_->verify_transparency_log(log_entry, cert);
  // ASSERT_TRUE(result.has_error());

  // result = verifier_->verify_bundle_consistency(log_entry, bundle);
  // ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofTreeSize)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.erase(obj.find("treeSize"));
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofTreeSize1)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      obj.find("treeSize")->value() = "0";
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofTreeSize2)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
      obj.find("treeSize")->value() = "999999999";
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofTreeSize3)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.find("treeSize")->value() = "foo";
    });
  });

  ASSERT_TRUE(log.has_error());
  // auto &[log_entry, bundle, cert] = log.value();

  // auto result = verifier_->verify_transparency_log(log_entry, cert);
  // ASSERT_TRUE(result.has_error());

  // result = verifier_->verify_bundle_consistency(log_entry, bundle);
  // ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofRootHash)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.erase(obj.find("rootHash"));
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofRootHash)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.find("rootHash")->value() = "foo";
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoInclusionProofHashes)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) { obj.erase(obj.find("hashes")); });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofHashes)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      auto &hashes = obj.find("hashes")->value().as_array();
      hashes[0] = "invalid-hash";
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error()); // TODO: check

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_EmptyInclusionProofHashes)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
      obj.find("hashes")->value() = boost::json::array{};
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpoint1)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
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

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpoint2)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
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

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointInconsistentTreeSize)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
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

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointTreeSizeWrongType)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
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

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointNoBody)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
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

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointNoSeparator)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
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

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointNoNewLine)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [](boost::json::object &obj) {
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

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionProofCheckpointWrongSignature)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionProof", [&](boost::json::object &obj) {
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

  auto &[log_entry, bundle, cert] = log.value();

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
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj.erase(obj.find("mediaType"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidMediaType)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.as_object();
    obj.find("mediaType")->value() = "invalid/media-type";
  });
  ASSERT_TRUE(log.has_error());
}

// =============================================================================
// Certificate Tests
// =============================================================================

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoCertificate)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial").as_object();
    obj.erase(obj.find("certificate"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoCertificateRawBytes)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/certificate").as_object();
    obj.erase(obj.find("rawBytes"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidCertificateRawBytes)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
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
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial").as_object();
    obj.erase(obj.find("tlogEntries"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_EmptyTlogEntries)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial").as_object();
    obj.find("tlogEntries")->value() = boost::json::array{};
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoTlogEntryLogIndex)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) { obj.erase(obj.find("logIndex")); });
  });
  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidTlogEntryLogIndex)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      obj.find("logIndex")->value() = "invalid-log-index";
    });
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoLogId)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
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

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_LogIdWrongType)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      auto *it = obj.find("logId");
      obj.erase(it);
      obj["logId"] = "invalid-log-id-type";
    });
  });

  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoLogIdKeyId)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/tlogEntries/0/logId").as_object();
    obj.erase(obj.find("keyId"));
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidLogIdKeyId)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/tlogEntries/0/logId").as_object();
    obj.find("keyId")->value() = "invalid-key-id";
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoKindVersion)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &obj = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    obj.erase(obj.find("kindVersion"));
  });
  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidKindVersionWrongType)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    o.erase(o.find("kindVersion"));
    o["kindVersion"] = "invalid-kind-version-type";
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoKindVersionKind)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.erase(o.find("kind"));
  });
  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidKindVersionKind)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.find("kind")->value() = "invalid-kind";
  });
  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoKindVersionVersion)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.erase(o.find("version"));
  });
  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidKindVersionVersion)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0/kindVersion").as_object();
    o.find("version")->value() = "invalid-version";
  });
  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoIntegratedTime)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) { obj.erase(obj.find("integratedTime")); });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidIntegratedTime1)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      obj.find("integratedTime")->value() = "invalid-time";
    });
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidIntegratedTime2)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) { obj.find("integratedTime")->value() = true; });
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_IntegratedTimeOutOfRange)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      obj.find("integratedTime")->value() = "1752174767";
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_IntegratedTimeFuture)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0", [](boost::json::object &obj) {
      auto current_time = std::chrono::system_clock::now();
      auto out_of_range_time = std::chrono::duration_cast<std::chrono::seconds>(current_time.time_since_epoch()).count() + 1000000;
      obj.find("integratedTime")->value() = std::to_string(out_of_range_time);
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoInclusionPromise)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    o.erase(o.find("inclusionPromise"));
  });
  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InclusionPromiseWrongType)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/verificationMaterial/tlogEntries/0").as_object();
    o.erase(o.find("inclusionPromise"));
    o["inclusionPromise"] = "invalid-inclusion-promise-type";
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoInclusionPromiseSignedEntryTimestamp)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionPromise", [](boost::json::object &obj) {
      obj.erase(obj.find("signedEntryTimestamp"));
    });
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_TRUE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidInclusionPromiseSignedEntryTimestamp)
{
  auto log = load_standard_bundle([this](boost::json::value &json_val) {
    apply_json_patch(json_val, "/verificationMaterial/tlogEntries/0/inclusionPromise", [](boost::json::object &obj) {
      obj.find("signedEntryTimestamp")->value() = "invalid-timestamp";
    });
  });
  ASSERT_TRUE(log.has_error());
}

// =============================================================================
// messageSignature Tests
// =============================================================================

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoMessageSignature)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.as_object();
    o.erase(o.find("messageSignature"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoMessageDigest)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature").as_object();
    o.erase(o.find("messageDigest"));
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoMessageDigestAlgorithm)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.erase(o.find("algorithm"));
  });

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_FALSE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidMessageDigestAlgorithm)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.find("algorithm")->value() = "INVALID_ALGO";
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoMessageDigestDigest)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.erase(o.find("digest"));
  });
  ASSERT_FALSE(log.has_error());

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidMessageDigestDigest)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature/messageDigest").as_object();
    o.find("digest")->value() = "invalid-digest";
  });
  ASSERT_FALSE(log.has_error());

  auto &[log_entry, bundle, cert] = log.value();

  auto result = verifier_->verify_transparency_log(log_entry, cert);
  ASSERT_FALSE(result.has_error());

  result = verifier_->verify_bundle_consistency(log_entry, bundle);
  ASSERT_TRUE(result.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_NoMessageSignatureSignature)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature").as_object();
    o.erase(o.find("signature"));
  });
  ASSERT_TRUE(log.has_error());
}

TEST_F(TransparencyLogVerifierTest, ValidateLog_InvalidMessageSignatureSignature)
{
  auto log = load_standard_bundle([](boost::json::value &json_val) {
    auto &o = json_val.at_pointer("/messageSignature").as_object();
    o.find("signature")->value() = "invalid-signature";
  });
  ASSERT_TRUE(log.has_error());
}
