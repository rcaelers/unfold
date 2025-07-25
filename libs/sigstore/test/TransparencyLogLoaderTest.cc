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
#include <filesystem>
#include <fstream>

#include "TransparencyLogLoader.hh"
#include "sigstore_rekor.pb.h"

namespace unfold::sigstore::test
{
  class TransparencyLogLoaderTest : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      loader = std::make_unique<TransparencyLogLoader>();

      // Create a temporary directory for test files
      temp_dir = std::filesystem::temp_directory_path() / "rekor_test";
      std::filesystem::create_directories(temp_dir);
    }

    void TearDown() override
    {
      // Clean up temporary directory
      if (std::filesystem::exists(temp_dir))
        {
          std::filesystem::remove_all(temp_dir);
        }
    }

    std::string create_sample_json()
    {
      return R"({
      "logIndex": "12345",
      "logId": {
        "keyId": "aGVsbG8gd29ybGQ="
      },
      "kindVersion": {
        "kind": "hashedrekord",
        "version": "0.0.1"
      },
      "integratedTime": "1640995200",
      "inclusionPromise": {
        "signedEntryTimestamp": "c2lnbmVkIGVudHJ5IHRpbWVzdGFtcA=="
      },
      "inclusionProof": {
        "logIndex": "12345",
        "rootHash": "cm9vdCBoYXNo",
        "treeSize": "12346",
        "hashes": [
          "aGFzaDEK",
          "aGFzaDIK"
        ],
        "checkpoint": {
          "envelope": "rekor.sigstore.dev - 1193050959916656506\n12346\ncm9vdCBoYXNo\n\n— rekor.sigstore.dev wNI9ajBEAiABTiAWtwgfG48x0M/ho0ynGbJ2QVuTb0mK5I0xHTIdPgIgFtivSy5vuhrlRlV2ZXM7267vYVQFlhhYHT/GeQlMfCM="
        }
      },
      "canonicalizedBody": "ewogICJhcGlWZXJzaW9uIjogIjAuMC4xIiwKICAia2luZCI6ICJoYXNoZWRyZWtvcmQiLAogICJzcGVjIjoge30KfQ=="
    })";
    }

    std::unique_ptr<TransparencyLogLoader> loader;
    std::filesystem::path temp_dir;
  };

  TEST_F(TransparencyLogLoaderTest, LoadFromJsonString)
  {
    std::string json_content = create_sample_json();

    auto result = loader->load_from_json(json_content);
    ASSERT_TRUE(result.has_value()) << "Failed to load JSON: " << result.error().message();

    const auto &entry = result.value();
    ASSERT_NE(entry, nullptr);

    // Verify basic fields
    EXPECT_EQ(entry->log_index(), 12345);
    EXPECT_EQ(entry->integrated_time(), 1640995200);

    // Verify kind_version
    ASSERT_TRUE(entry->has_kind_version());
    EXPECT_EQ(entry->kind_version().kind(), "hashedrekord");
    EXPECT_EQ(entry->kind_version().version(), "0.0.1");

    // Verify inclusion_proof
    ASSERT_TRUE(entry->has_inclusion_proof());
    EXPECT_EQ(entry->inclusion_proof().log_index(), 12345);
    EXPECT_EQ(entry->inclusion_proof().tree_size(), 12346);
    EXPECT_EQ(entry->inclusion_proof().hashes_size(), 2);

    // Verify checkpoint
    ASSERT_TRUE(entry->inclusion_proof().has_checkpoint());
    EXPECT_TRUE(entry->inclusion_proof().checkpoint().envelope().find("rekor.sigstore.dev") != std::string::npos);
  }

  TEST_F(TransparencyLogLoaderTest, LoadFromFile)
  {
    // Create a test file
    std::filesystem::path test_file = temp_dir / "test_rekor.json";
    std::ofstream file(test_file);
    file << create_sample_json();
    file.close();

    auto result = loader->load_from_file(test_file);
    ASSERT_TRUE(result.has_value()) << "Failed to load file: " << result.error().message();

    const auto &entry = result.value();
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->log_index(), 12345);
  }

  TEST_F(TransparencyLogLoaderTest, InvalidJsonString)
  {
    std::string invalid_json = "{ invalid json content";

    auto result = loader->load_from_json(invalid_json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(TransparencyLogLoaderTest, MissingRequiredFields)
  {
    // Test missing kind_version
    std::string json_missing_kind = R"({
    "logIndex": "12345",
          "verificationMaterial": {
              "tlogEntries": [ {
                  "inclusionProof": {
                    "logIndex": "12345",
                    "rootHash": "cm9vdCBoYXNo",
                    "treeSize": "12346",
                    "hashes": []
                  }
              }]
        }
      }
    })";

    auto result = loader->load_from_json(json_missing_kind);
    EXPECT_FALSE(result.has_value());

    // Test missing inclusion_proof
    std::string json_missing_proof = R"({
    "logIndex": "12345",
          "verificationMaterial": {
              "tlogEntries": [ {
                  "kindVersion": {
                      "kind": "hashedrekord",
                      "version": "0.0.1"
                  }
              }]
        }
      }
      })";

    result = loader->load_from_json(json_missing_proof);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(TransparencyLogLoaderTest, MinimalValidJson)
  {
    // Test with only required fields
    std::string minimal_json = R"({
    "logIndex": "12345",
    "kindVersion": {
      "kind": "hashedrekord",
      "version": "0.0.1"
    },
    "inclusionProof": {
      "logIndex": "12345",
      "rootHash": "cm9vdCBoYXNo",
      "treeSize": "12346",
      "hashes": []
    }
  })";

    auto result = loader->load_from_json(minimal_json);
    ASSERT_TRUE(result.has_value()) << "Failed to load minimal JSON: " << result.error().message();

    const auto &entry = result.value();
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->log_index(), 12345);
    EXPECT_FALSE(entry->has_log_id());
    EXPECT_FALSE(entry->has_inclusion_promise());
  }

  TEST_F(TransparencyLogLoaderTest, FileNotFound)
  {
    std::filesystem::path nonexistent_file = temp_dir / "nonexistent.json";

    auto result = loader->load_from_file(nonexistent_file);
    EXPECT_FALSE(result.has_value());
  }

} // namespace unfold::sigstore::test
