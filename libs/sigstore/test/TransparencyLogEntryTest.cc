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

#include "TransparencyLogEntry.hh"

using namespace unfold::sigstore;

class TransparencyLogEntryTest : public ::testing::Test
{
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
