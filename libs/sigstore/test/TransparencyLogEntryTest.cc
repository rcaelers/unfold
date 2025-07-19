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
#include <boost/json.hpp>
#include <fstream>
#include <filesystem>
#include <sstream>

#include "TransparencyLogEntry.hh"

using namespace unfold::sigstore;

class TransparencyLogEntryTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // Test setup - no longer loads files globally for performance
  }

  // Helper method to load API test data only when needed
  boost::json::value load_api_data()
  {
    std::filesystem::path current_path = std::filesystem::current_path();
    std::filesystem::path test_file = current_path / "test" / "data" / "tlog.json";
    
    if (!std::filesystem::exists(test_file))
      {
        return boost::json::value();
      }

    std::ifstream file(test_file);
    if (!file.is_open())
      {
        return boost::json::value();
      }

    std::stringstream buffer;
    buffer << file.rdbuf();
    
    boost::system::error_code ec;
    auto result = boost::json::parse(buffer.str(), ec);
    return ec ? boost::json::value() : result;
  }
};

TEST_F(TransparencyLogEntryTest, ParseMinimalEntry)
{
  // Test with minimal required fields
  std::string json_str = R"({
    "logIndex": "270584577"
  })";

  auto json_val = boost::json::parse(json_str);

  TransparencyLogEntryParser parser;
  auto result = parser.parse(json_val);

  ASSERT_TRUE(result) << "Failed to parse minimal transparency log entry";

  const auto &entry = result.value();
  EXPECT_EQ(entry.log_index, 270584577);
  EXPECT_FALSE(entry.log_id.has_value());
  EXPECT_FALSE(entry.kind_version.has_value());
  EXPECT_FALSE(entry.integrated_time.has_value());
}

TEST_F(TransparencyLogEntryTest, ParseCompleteEntry)
{
  // Test with complete transparency log entry
  std::string json_str = R"({
    "logIndex": "270584577",
    "logId": {
      "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
    },
    "kindVersion": {
      "kind": "hashedrekord",
      "version": "0.0.1"
    },
    "integratedTime": "1752170767",
    "inclusionPromise": {
      "signedEntryTimestamp": "MEQCIHDgARv5w39YWiRPb0TkbcHwnMhXaXgao5bl0URtdkt3AiBLlm6X2gN8WFCZAdwAl3vVIZNrRsHDTJQKXS8I5Uzjpg=="
    },
    "inclusionProof": {
      "logIndex": "148680315",
      "rootHash": "Lhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=",
      "treeSize": "148680319",
      "hashes": [
        "9Aovr8Qf/msvXgQqLqhf1LAs+/CukHR0/4WmxjZUB2s=",
        "hAqpG6BebLlqxm/j0PZpJEyMMBKcP1CnheqCpMWsZ2s="
      ],
      "checkpoint": {
        "envelope": "rekor.sigstore.dev - 1193050959916656506\n148680319\nLhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=\n\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM=\n"
      }
    },
    "canonicalizedBody": "eyJhcGlWZXJzaW9uIjoi..."
  })";

  auto json_val = boost::json::parse(json_str);

  TransparencyLogEntryParser parser;
  auto result = parser.parse(json_val);

  ASSERT_TRUE(result) << "Failed to parse complete transparency log entry";

  const auto &entry = result.value();

  // Verify basic fields
  EXPECT_EQ(entry.log_index, 270584577);
  EXPECT_TRUE(entry.integrated_time.has_value());
  EXPECT_EQ(entry.integrated_time.value(), 1752170767);

  // Verify logId
  ASSERT_TRUE(entry.log_id.has_value());
  EXPECT_EQ(entry.log_id, "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d");

  // Verify kindVersion
  ASSERT_TRUE(entry.kind_version.has_value());
  EXPECT_EQ(entry.kind_version->kind, "hashedrekord");
  EXPECT_EQ(entry.kind_version->version, "0.0.1");

  // Verify inclusionPromise
  ASSERT_TRUE(entry.inclusion_promise.has_value());
  EXPECT_EQ(entry.inclusion_promise->signed_entry_timestamp,
            "MEQCIHDgARv5w39YWiRPb0TkbcHwnMhXaXgao5bl0URtdkt3AiBLlm6X2gN8WFCZAdwAl3vVIZNrRsHDTJQKXS8I5Uzjpg==");

  // Verify inclusionProof
  ASSERT_TRUE(entry.inclusion_proof.has_value());
  EXPECT_EQ(entry.inclusion_proof->log_index, 148680315);
  EXPECT_EQ(entry.inclusion_proof->root_hash, "Lhfph6Lh1x0tstJX8Fc7lFBSos1pMUaTmgnyhvy+fQo=");
  EXPECT_EQ(entry.inclusion_proof->tree_size, 148680319);
  EXPECT_EQ(entry.inclusion_proof->hashes.size(), 2);
  EXPECT_EQ(entry.inclusion_proof->hashes[0], "9Aovr8Qf/msvXgQqLqhf1LAs+/CukHR0/4WmxjZUB2s=");

  // Verify checkpoint
  ASSERT_TRUE(entry.inclusion_proof->checkpoint.has_value());
  EXPECT_TRUE(entry.inclusion_proof->checkpoint->envelope.find("rekor.sigstore.dev") != std::string::npos);

  // Verify body (unified field)
  ASSERT_TRUE(entry.body.has_value());
  EXPECT_EQ(entry.body.value(), "eyJhcGlWZXJzaW9uIjoi...");
}

TEST_F(TransparencyLogEntryTest, ParseIntegerLogIndex)
{
  // Test with integer logIndex instead of string
  std::string json_str = R"({
    "logIndex": 270584577
  })";

  auto json_val = boost::json::parse(json_str);

  TransparencyLogEntryParser parser;
  auto result = parser.parse(json_val);

  ASSERT_TRUE(result) << "Failed to parse integer logIndex";

  const auto &entry = result.value();
  EXPECT_EQ(entry.log_index, 270584577);
}

TEST_F(TransparencyLogEntryTest, ParseInvalidEntry)
{
  // Test with missing required logIndex
  std::string json_str = R"({
    "someOtherField": "value"
  })";

  auto json_val = boost::json::parse(json_str);

  TransparencyLogEntryParser parser;
  auto result = parser.parse(json_val);

  EXPECT_FALSE(result) << "Should fail when logIndex is missing";
}

// API Response Tests

TEST_F(TransparencyLogEntryTest, ParseApiResponseStructure)
{
  auto api_json = load_api_data();
  if (!api_json.is_object())
    {
      GTEST_SKIP() << "tlog.json not available or invalid";
    }

  const auto &root_obj = api_json.as_object();
  ASSERT_FALSE(root_obj.empty());

  // Get the first entry (should be keyed by entry UUID)
  const auto &entry_pair = *root_obj.begin();
  const auto &entry_data = entry_pair.value();

  ASSERT_TRUE(entry_data.is_object());
  const auto &entry_obj = entry_data.as_object();

  // Verify expected fields are present
  EXPECT_TRUE(entry_obj.contains("body"));
  EXPECT_TRUE(entry_obj.contains("integratedTime"));
  EXPECT_TRUE(entry_obj.contains("logID"));
  EXPECT_TRUE(entry_obj.contains("logIndex"));
  EXPECT_TRUE(entry_obj.contains("verification"));

  // Verify verification section structure
  const auto &verification = entry_obj.at("verification");
  ASSERT_TRUE(verification.is_object());
  const auto &verification_obj = verification.as_object();

  EXPECT_TRUE(verification_obj.contains("inclusionProof"));
  EXPECT_TRUE(verification_obj.contains("signedEntryTimestamp"));
}

TEST_F(TransparencyLogEntryTest, ParseApiResponseWithParser)
{
  auto api_json = load_api_data();
  if (!api_json.is_object())
    {
      GTEST_SKIP() << "tlog.json not available or invalid";
    }

  TransparencyLogEntryParser parser;
  auto result = parser.parse_api_response(api_json);

  ASSERT_TRUE(result.has_value()) << "Failed to parse API response: " << result.error().message();

  const auto &entry = result.value();

  // Verify basic fields
  EXPECT_GT(entry.log_index, 0);
  EXPECT_TRUE(entry.integrated_time.has_value());
  EXPECT_TRUE(entry.body.has_value());
  EXPECT_TRUE(entry.log_id.has_value());
  EXPECT_FALSE(entry.log_id.value().empty());

  // Verify that API verification section was mapped to bundle fields
  EXPECT_TRUE(entry.inclusion_proof.has_value());
  EXPECT_TRUE(entry.inclusion_promise.has_value());

  // Verify inclusion proof details
  const auto &inclusion_proof = entry.inclusion_proof.value();
  EXPECT_GT(inclusion_proof.log_index, 0);
  EXPECT_FALSE(inclusion_proof.root_hash.empty());
  EXPECT_GT(inclusion_proof.tree_size, 0);
  EXPECT_FALSE(inclusion_proof.hashes.empty());

  // Verify checkpoint if present
  if (inclusion_proof.checkpoint.has_value())
    {
      EXPECT_FALSE(inclusion_proof.checkpoint.value().envelope.empty());
    }

  // Verify inclusion promise (mapped from signedEntryTimestamp)
  const auto &inclusion_promise = entry.inclusion_promise.value();
  EXPECT_FALSE(inclusion_promise.signed_entry_timestamp.empty());
}

TEST_F(TransparencyLogEntryTest, VerifyApiFieldsPopulated)
{
  auto api_json = load_api_data();
  if (!api_json.is_object())
    {
      GTEST_SKIP() << "tlog.json not available or invalid";
    }

  TransparencyLogEntryParser parser;
  auto result = parser.parse_api_response(api_json);

  ASSERT_TRUE(result.has_value());
  const auto &entry = result.value();

  // Verify API-specific fields are populated correctly
  EXPECT_TRUE(entry.body.has_value());
  EXPECT_FALSE(entry.body.value().empty());

  EXPECT_TRUE(entry.log_id.has_value());
  EXPECT_FALSE(entry.log_id.value().empty());

  EXPECT_TRUE(entry.integrated_time.has_value());
  EXPECT_EQ(entry.integrated_time.value(), 1752170767); // From tlog.json

  EXPECT_EQ(entry.log_index, 270584577); // From tlog.json

  // Verify that verification section was mapped to bundle fields
  ASSERT_TRUE(entry.inclusion_proof.has_value());
  const auto &inclusion_proof = entry.inclusion_proof.value();

  EXPECT_EQ(inclusion_proof.log_index, 148680315); // From tlog.json verification
  EXPECT_EQ(inclusion_proof.tree_size, 151165654); // From tlog.json verification
  EXPECT_EQ(inclusion_proof.hashes.size(), 26);    // From tlog.json verification

  // Verify that signedEntryTimestamp was mapped to inclusion_promise
  EXPECT_TRUE(entry.inclusion_promise.has_value());
  EXPECT_FALSE(entry.inclusion_promise.value().signed_entry_timestamp.empty());
}

TEST_F(TransparencyLogEntryTest, BackwardCompatibilityWithBundleFormat)
{
  // Create a simple bundle-style JSON for comparison
  constexpr int64_t TEST_LOG_INDEX = 123456;
  boost::json::object bundle_entry = {{"logIndex", TEST_LOG_INDEX},
                                      {"integratedTime", "1752170767"},
                                      {"canonicalizedBody", "dGVzdCBkYXRh"}, // base64 "test data"
                                      {"logId", {{"keyId", "test-key-id"}}}};

  TransparencyLogEntryParser parser;
  auto result = parser.parse(bundle_entry);

  ASSERT_TRUE(result.has_value());
  const auto &entry = result.value();

  EXPECT_EQ(entry.log_index, TEST_LOG_INDEX);
  EXPECT_TRUE(entry.integrated_time.has_value());
  EXPECT_EQ(entry.integrated_time.value(), 1752170767);
  EXPECT_TRUE(entry.body.has_value()); // Now unified body field
  EXPECT_TRUE(entry.log_id.has_value());
  EXPECT_FALSE(entry.log_id.value().empty());
}

TEST_F(TransparencyLogEntryTest, HandleMissingVerificationSection)
{
  auto api_json = load_api_data();
  if (!api_json.is_object())
    {
      GTEST_SKIP() << "tlog.json not available or invalid";
    }

  // Test with API response structure but missing verification section
  const auto &root_obj = api_json.as_object();
  const auto &entry_pair = *root_obj.begin();
  auto entry_data = entry_pair.value().as_object();

  // Remove verification section
  entry_data.erase("verification");

  boost::json::object test_root;
  test_root[entry_pair.key()] = entry_data;

  TransparencyLogEntryParser parser;
  auto result = parser.parse_api_response(test_root);

  ASSERT_TRUE(result.has_value());
  const auto &entry = result.value();

  // Should still parse basic fields
  EXPECT_GT(entry.log_index, 0);
  EXPECT_TRUE(entry.integrated_time.has_value());
  EXPECT_TRUE(entry.body.has_value());

  // But verification-related fields should be empty since verification section was removed
  EXPECT_FALSE(entry.inclusion_proof.has_value());
  EXPECT_FALSE(entry.inclusion_promise.has_value());
}
