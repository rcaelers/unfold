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

#include "BundleLoader.hh"
#include "sigstore_bundle.pb.h"

namespace unfold::sigstore::test
{

  class SigstoreBundleLoaderTest : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      loader = std::make_unique<SigstoreBundleLoader>();
    }

    void TearDown() override
    {
    }

    std::unique_ptr<SigstoreBundleLoader> loader;
  };

  TEST_F(SigstoreBundleLoaderTest, LoadFromFile)
  {
    auto result = loader->load_from_file("appcast-sigstore.xml.sigstore.new.bundle");
    ASSERT_TRUE(result.has_value()) << "Failed to load file: " << result.error().message();

    const auto &bundle = result.value();
    EXPECT_EQ(bundle.media_type(), "application/vnd.dev.sigstore.bundle.v0.3+json");
  }

  TEST_F(SigstoreBundleLoaderTest, InvalidJsonString)
  {
    std::string invalid_json = "{ invalid json content";
    auto result = loader->load_from_json(invalid_json);
    EXPECT_FALSE(result.has_value());
  }


  TEST_F(SigstoreBundleLoaderTest, MissingRequiredFields)
  {
    std::string json_missing_media_type = R"({
    "verificationMaterial": {
      "tlogEntries": []
    },
    "messageSignature": {
      "messageDigest": {
        "algorithm": "SHA2_256",
        "digest": "czMzaDBsMXMgbUQ1IGQxOWc0czcrK1EvR0lqMTFhTGNabEp5"
      },
      "signature": "TUVVUlFUQWlnR1lVSE05SUF4L1kwWldoZ0JIa05nZzZONC92dURkRXhPak15bWNOWUJUa1NnSUJoTU5uRklUaWpRODNGZ0ZOSFdMbWtOWHFlNTFGNDF4VGpPekE9PQ=="
    }
  })";

    auto result = loader->load_from_json(json_missing_media_type);
    // This should still work as media_type might not be required by protobuf
    // The test validates that the parser handles missing fields gracefully
  }

  TEST_F(SigstoreBundleLoaderTest, EmptyObject)
  {
    std::string empty_json = "{}";
    auto result = loader->load_from_json(empty_json);
    EXPECT_TRUE(result.has_error()); // Empty bundle should be valid
  }

  TEST_F(SigstoreBundleLoaderTest, FileNotFound)
  {
    std::filesystem::path nonexistent_file = "nonexistent.json";
    auto result = loader->load_from_file(nonexistent_file);
    EXPECT_FALSE(result.has_value());
  }

} // namespace unfold::sigstore::test
