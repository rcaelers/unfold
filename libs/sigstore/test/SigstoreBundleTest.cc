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
#include <fstream>

#include "SigstoreStandardBundle.hh"
#include "SigstoreBundleBase.hh"

using namespace unfold::sigstore;

class SigstoreBundleTest : public ::testing::Test
{
};

TEST_F(SigstoreBundleTest, ParseStandardBundle)
{
  std::ifstream file("appcast-sigstore.xml.sigstore.new.bundle");
  ASSERT_TRUE(file.is_open()) << "Failed to open bundle";
  std::string json((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  file.close();

  auto bundle_result = SigstoreBundleBase::from_json(json);
  ASSERT_TRUE(bundle_result) << "Failed to parse standard bundle";

  auto bundle = std::move(bundle_result.value());
  ASSERT_NE(bundle, nullptr);

  // Verify certificate is present
  EXPECT_EQ(bundle->get_certificate().oidc_issuer(), "https://github.com/login/oauth");
  EXPECT_EQ(bundle->get_certificate().subject_email(), "rob.caelers@gmail.com");
  EXPECT_FALSE(bundle->get_certificate().is_self_signed());

  EXPECT_FALSE(bundle->get_signature().empty());

  EXPECT_EQ(bundle->get_log_index(), 270584577);

  auto *standard_bundle = dynamic_cast<SigstoreStandardBundle *>(bundle.get());
  ASSERT_NE(standard_bundle, nullptr);

  auto algorithm = standard_bundle->get_algorithm();
  EXPECT_TRUE(algorithm.has_value());
  EXPECT_EQ(algorithm.value(), "SHA2_256");
  
  auto digest = standard_bundle->get_message_digest();
  EXPECT_TRUE(digest.has_value());
  EXPECT_FALSE(digest.value().empty());
  
  EXPECT_FALSE(standard_bundle->get_signature().empty());
}

TEST_F(SigstoreBundleTest, ParseLegacyBundle)
{
  std::ifstream file("appcast-sigstore.xml.sigstore.bundle");
  ASSERT_TRUE(file.is_open()) << "Failed to open legacy bundle";
  std::string json((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  file.close();

  auto bundle_result = SigstoreBundleBase::from_json(json);
  ASSERT_TRUE(bundle_result) << "Failed to parse legacy bundle";

  auto bundle = std::move(bundle_result.value());
  ASSERT_NE(bundle, nullptr);

  EXPECT_EQ(bundle->get_signature(),
            "MEUCID1iKgR4BeZTz+zoHqocEDZ/zWgFD2P3dUZJ0AuQqJxmAiEA9g/4S9fhwuh4VPQ8eRhkO2x8SN2X2J8BjfOSxnFrDzw=");
  EXPECT_EQ(bundle->get_certificate().oidc_issuer(), "https://github.com/login/oauth");
  EXPECT_EQ(bundle->get_certificate().subject_email(), "rob.caelers@gmail.com");
  EXPECT_FALSE(bundle->get_certificate().is_self_signed());
  EXPECT_EQ(bundle->get_log_index(), 268807149);
}

TEST_F(SigstoreBundleTest, InvalidBundle)
{
  auto result1 = SigstoreBundleBase::from_json("invalid json");
  EXPECT_FALSE(result1);

  auto result2 = SigstoreBundleBase::from_json(R"({"unknown": "format"})");
  EXPECT_FALSE(result2);

  auto result3 = SigstoreBundleBase::from_json("{}");
  EXPECT_FALSE(result3);
}
