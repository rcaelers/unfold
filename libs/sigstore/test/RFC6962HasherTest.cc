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
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <array>

#include "RFC6962Hasher.hh"

namespace unfold::sigstore::test
{

  class RFC6962HasherTest : public ::testing::Test
  {
  protected:
    RFC6962Hasher hasher_;

    // Helper function to convert binary hash to hex string for easier comparison
    static std::string to_hex(const std::string &binary)
    {
      std::stringstream ss;
      for (unsigned char c: binary)
        {
          ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
      return ss.str();
    }
    // Helper function to compute expected hash manually for verification
    static std::string compute_expected_sha256(const std::string &data)
    {
      std::array<unsigned char, SHA256_DIGEST_LENGTH> hash{};
      SHA256(reinterpret_cast<const unsigned char *>(data.c_str()), data.length(), hash.data());
      return std::string(reinterpret_cast<char *>(hash.data()), SHA256_DIGEST_LENGTH);
    }
  };

  TEST_F(RFC6962HasherTest, TestHashLeaf)
  {
    const std::string test_data = "test data";

    // Compute hash using our implementation
    std::string result = hasher_.hash_leaf(test_data);
    ASSERT_FALSE(result.empty());
    EXPECT_EQ(result.length(), SHA256_DIGEST_LENGTH);

    // Compute expected hash manually: SHA256(0x00 || "test data")
    std::string expected_input = std::string(1, 0x00) + test_data;
    std::string expected_hash = compute_expected_sha256(expected_input);

    EXPECT_EQ(result, expected_hash);
  }

  TEST_F(RFC6962HasherTest, TestHashChildren)
  {
    const std::string left_hash = "left_hash_32_bytes_test_data_1234";  // 32 bytes
    const std::string right_hash = "right_hash_32_bytes_test_data_123"; // 32 bytes

    // Compute hash using our implementation
    std::string result = hasher_.hash_children(left_hash, right_hash);
    ASSERT_FALSE(result.empty());
    EXPECT_EQ(result.length(), SHA256_DIGEST_LENGTH);

    // Compute expected hash manually: SHA256(0x01 || left_hash || right_hash)
    std::string expected_input = std::string(1, 0x01) + left_hash + right_hash;
    std::string expected_hash = compute_expected_sha256(expected_input);

    EXPECT_EQ(result, expected_hash);
  }

  TEST_F(RFC6962HasherTest, TestHashLeafEmptyData)
  {
    // Test with empty data
    std::string result = hasher_.hash_leaf("");
    ASSERT_FALSE(result.empty());
    EXPECT_EQ(result.length(), SHA256_DIGEST_LENGTH);

    // Compute expected hash manually: SHA256(0x00)
    std::string expected_input = std::string(1, 0x00);
    std::string expected_hash = compute_expected_sha256(expected_input);

    EXPECT_EQ(result, expected_hash);
  }

  TEST_F(RFC6962HasherTest, TestHashChildrenEmptyData)
  {
    // Test with empty hashes
    std::string result = hasher_.hash_children("", "");
    ASSERT_FALSE(result.empty());
    EXPECT_EQ(result.length(), SHA256_DIGEST_LENGTH);

    // Compute expected hash manually: SHA256(0x01)
    std::string expected_input = std::string(1, 0x01);
    std::string expected_hash = compute_expected_sha256(expected_input);

    EXPECT_EQ(result, expected_hash);
  }

  TEST_F(RFC6962HasherTest, TestDifferentPrefixes)
  {
    const std::string test_data = "same data";

    // Hash as leaf and as if it were children (should be different due to prefixes)
    std::string leaf_hash = hasher_.hash_leaf(test_data);
    std::string children_hash = hasher_.hash_children(test_data, "");

    ASSERT_FALSE(leaf_hash.empty());
    ASSERT_FALSE(children_hash.empty());
    EXPECT_NE(leaf_hash, children_hash);
  }

} // namespace unfold::sigstore::test
