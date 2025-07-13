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

#include "../src/SignatureVerifier.hh"
#include "../src/Certificate.hh"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

namespace
{
  const auto *const pem = R"(-----BEGIN CERTIFICATE-----
MIIC0zCCAlqgAwIBAgIUYFPFMu0cnyfOHpM6mReGmYXv0a0wCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjUwNzA5MTgwMjQ2WhcNMjUwNzA5MTgxMjQ2WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEXqsGYRZ1J8HzmrXj1YQgImCb9ID9SLOwMPf4
3ZNEqZ9X7iS1HWvZ4618h5QjJNjn710qcZaQY5eMuNjevpW9WaOCAXkwggF1MA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUvFyp
Vql0k/nBFMqct8PqqlXeOcEwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQB
g78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/
MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHW
eQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAAB
l/BatuEAAAQDAEcwRQIgHfTWqEtNiKJdIP3Hlx3jfpTlE5EKLrzQaDr8XNod/l8C
IQCO41Lry0E0RgCk12NjzXLgI3fX90IMbjYOCi7qpJ1pojAKBggqhkjOPQQDAwNn
ADBkAjBDxtCzMBi9uGaYflFklkHb9gaI1AepSy9DxRuIegdsLnvtHNd3rLwbfPqJ
ZOw4B4QCMB41oC+O1hO15qi1LtQVBmzkXLtWIy6youHR1ksJCMY9imNWVe+pUJQM
/4lxvj7/qg==
-----END CERTIFICATE-----)";
}

namespace unfold::sigstore::test
{

  class SignatureVerifierTest : public ::testing::Test
  {
  public:
    std::unique_ptr<SignatureVerifier> &verifier()
    {
      return verifier_;
    }

  protected:
    void SetUp() override
    {
      verifier_ = std::make_unique<SignatureVerifier>();
    }

  private:
    std::unique_ptr<SignatureVerifier> verifier_;
  };

  TEST_F(SignatureVerifierTest, ValidSignature)
  {
    std::ifstream file("appcast-sigstore.xml");
    ASSERT_TRUE(file.is_open()) << "Failed to open test/data/appcast-sigstore.xml";

    std::string appcast((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    auto cert = Certificate::from_pem(pem);
    EXPECT_TRUE(cert.has_value());

    std::string
      valid_sig_b64 = "MEUCID1iKgR4BeZTz+zoHqocEDZ/zWgFD2P3dUZJ0AuQqJxmAiEA9g/4S9fhwuh4VPQ8eRhkO2x8SN2X2J8BjfOSxnFrDzw=";

    auto result = verifier()->verify_signature(appcast, cert.value(), valid_sig_b64);

    EXPECT_FALSE(result.has_error());
    EXPECT_TRUE(result.value());
  }

  TEST_F(SignatureVerifierTest, InvalidSignature)
  {
    std::ifstream file("appcast-sigstore.xml");
    ASSERT_TRUE(file.is_open()) << "Failed to open test/data/appcast-sigstore.xml";

    std::string appcast((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    auto cert = Certificate::from_pem(pem);
    EXPECT_TRUE(cert.has_value());

    std::string
      invalid_sig_b64 = "mEUCID1iKgR4BeZTz+zoHqocEDZ/zWgFD2P3dUZJ0AuQqJxmAiEA9g/4S9fhwuh4VPQ8eRhkO2x8SN2X2J8BjfOSxnFrDzw=";

    auto result = verifier()->verify_signature(appcast, cert.value(), invalid_sig_b64);

    EXPECT_FALSE(result.has_error());
    EXPECT_FALSE(result.value());
  }

} // namespace unfold::sigstore::test
