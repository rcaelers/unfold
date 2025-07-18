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

#include "Certificate.hh"
#include "CryptographicAlgorithms.hh"
#include "utils/Base64.hh"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

namespace unfold::sigstore::test
{
  class CertificateTest : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
    }
  };

  TEST_F(CertificateTest, ParseInvalidCertificate)
  {
    const std::string invalid_cert = "invalid certificate data";

    auto cert = Certificate::from_pem(invalid_cert);

    EXPECT_TRUE(cert.has_error());
  }

  TEST_F(CertificateTest, VerifyCertificateChainWithoutTrustBundle)
  {
    const std::string cert_pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";

    auto cert = Certificate::from_pem(cert_pem);
    EXPECT_FALSE(cert.has_value());
  }

  TEST_F(CertificateTest, VerifyCertificateChainWithTrustBundle)
  {
    auto cert = Certificate::from_pem(unfold::utils::Base64::decode(
      "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMwekNDQWxxZ0F3SUJBZ0lVWUZQRk11MGNueWZPSHBNNm1SZUdtWVh2MGEwd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpVd056QTVNVGd3TWpRMldoY05NalV3TnpBNU1UZ3hNalEyV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVYcXNHWVJaMUo4SHptclhqMVlRZ0ltQ2I5SUQ5U0xPd01QZjQKM1pORXFaOVg3aVMxSFd2WjQ2MThoNVFqSk5qbjcxMHFjWmFRWTVlTXVOamV2cFc5V2FPQ0FYa3dnZ0YxTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVV2RnlwClZxbDBrL25CRk1xY3Q4UHFxbFhlT2NFd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0l3WURWUjBSQVFIL0JCa3dGNEVWY205aUxtTmhaV3hsY25OQVoyMWhhV3d1WTI5dE1Dd0dDaXNHQVFRQgpnNzh3QVFFRUhtaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOXNiMmRwYmk5dllYVjBhREF1QmdvckJnRUVBWU8vCk1BRUlCQ0FNSG1oMGRIQnpPaTh2WjJsMGFIVmlMbU52YlM5c2IyZHBiaTl2WVhWMGFEQ0JpZ1lLS3dZQkJBSFcKZVFJRUFnUjhCSG9BZUFCMkFOMDlNR3JHeHhFeVl4a2VISmxuTndLaVNsNjQzanl0LzRlS2NvQXZLZTZPQUFBQgpsL0JhdHVFQUFBUURBRWN3UlFJZ0hmVFdxRXROaUtKZElQM0hseDNqZnBUbEU1RUtMcnpRYURyOFhOb2QvbDhDCklRQ080MUxyeTBFMFJnQ2sxMk5qelhMZ0kzZlg5MElNYmpZT0NpN3FwSjFwb2pBS0JnZ3Foa2pPUFFRREF3Tm4KQURCa0FqQkR4dEN6TUJpOXVHYVlmbEZrbGtIYjlnYUkxQWVwU3k5RHhSdUllZ2RzTG52dEhOZDNyTHdiZlBxSgpaT3c0QjRRQ01CNDFvQytPMWhPMTVxaTFMdFFWQm16a1hMdFdJeTZ5b3VIUjFrc0pDTVk5aW1OV1ZlK3BVSlFNCi80bHh2ajcvcWc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="));
    EXPECT_FALSE(cert.has_error());
    EXPECT_EQ(cert.value().oidc_issuer(), "https://github.com/login/oauth");
    EXPECT_EQ(cert.value().subject_email(), "rob.caelers@gmail.com");
    EXPECT_FALSE(cert.value().is_self_signed());
  }

  TEST_F(CertificateTest, ParseCertificateFromDER)
  {
    const std::string cert_der_base64 =
      "MIIC0zCCAlqgAwIBAgIUYFPFMu0cnyfOHpM6mReGmYXv0a0wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNzA5MTgwMjQ2WhcNMjUwNzA5MTgxMjQ2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXqsGYRZ1J8HzmrXj1YQgImCb9ID9SLOwMPf43ZNEqZ9X7iS1HWvZ4618h5QjJNjn710qcZaQY5eMuNjevpW9WaOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUvFypVql0k/nBFMqct8PqqlXeOcEwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABl/BatuEAAAQDAEcwRQIgHfTWqEtNiKJdIP3Hlx3jfpTlE5EKLrzQaDr8XNod/l8CIQCo41Lry0E0RgCk12NjzXLgI3fX90IMbjYOCi7qpJ1pojAKBggqhkjOPQQDAwNnADBkAjBDxtCzMBi9uGaYflFklkHb9gaI1AepSy9DxRuIegdsLnvtHNd3rLwbfPqJZOw4B4QCMb41oC+O1hO15qi1LtQVBmzkXLtWIy6youHR1ksJCMY9imNWVe+pUJQM/4lxvj7/qg==";

    auto cert_der_string = unfold::utils::Base64::decode(cert_der_base64);
    std::vector<uint8_t> cert_der_data(cert_der_string.begin(), cert_der_string.end());
    auto cert = Certificate::from_der(cert_der_data);

    EXPECT_FALSE(cert.has_error());
    EXPECT_EQ(cert.value().oidc_issuer(), "https://github.com/login/oauth");
    EXPECT_EQ(cert.value().subject_email(), "rob.caelers@gmail.com");
    EXPECT_FALSE(cert.value().is_self_signed());
  }

  TEST_F(CertificateTest, ParseInvalidCertificateFromDER)
  {
    const std::vector<uint8_t> invalid_cert_der = {0x00, 0x01, 0x02, 0x03};

    auto cert = Certificate::from_der(invalid_cert_der);

    EXPECT_TRUE(cert.has_error());
  }

  TEST_F(CertificateTest, ParseCertificateFromDERString)
  {
    const std::string cert_der_base64 =
      "MIIC0zCCAlqgAwIBAgIUYFPFMu0cnyfOHpM6mReGmYXv0a0wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNzA5MTgwMjQ2WhcNMjUwNzA5MTgxMjQ2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXqsGYRZ1J8HzmrXj1YQgImCb9ID9SLOwMPf43ZNEqZ9X7iS1HWvZ4618h5QjJNjn710qcZaQY5eMuNjevpW9WaOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUvFypVql0k/nBFMqct8PqqlXeOcEwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABl/BatuEAAAQDAEcwRQIgHfTWqEtNiKJdIP3Hlx3jfpTlE5EKLrzQaDr8XNod/l8CIQCo41Lry0E0RgCk12NjzXLgI3fX90IMbjYOCi7qpJ1pojAKBggqhkjOPQQDAwNnADBkAjBDxtCzMBi9uGaYflFklkHb9gaI1AepSy9DxRuIegdsLnvtHNd3rLwbfPqJZOw4B4QCMb41oC+O1hO15qi1LtQVBmzkXLtWIy6youHR1ksJCMY9imNWVe+pUJQM/4lxvj7/qg==";

    auto cert_der_string = unfold::utils::Base64::decode(cert_der_base64);
    auto cert = Certificate::from_der(cert_der_string);

    EXPECT_FALSE(cert.has_error());
    EXPECT_EQ(cert.value().oidc_issuer(), "https://github.com/login/oauth");
    EXPECT_EQ(cert.value().subject_email(), "rob.caelers@gmail.com");
    EXPECT_FALSE(cert.value().is_self_signed());
  }

  TEST_F(CertificateTest, VerifySignatureMethodExists)
  {
    // Test that the new verify_signature methods exist and can be called
    // We don't have real signature data, so we test with empty data to verify the API
    const std::string cert_der_base64 =
      "MIIC0zCCAlqgAwIBAgIUYFPFMu0cnyfOHpM6mReGmYXv0a0wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNzA5MTgwMjQ2WhcNMjUwNzA5MTgxMjQ2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXqsGYRZ1J8HzmrXj1YQgImCb9ID9SLOwMPf43ZNEqZ9X7iS1HWvZ4618h5QjJNjn710qcZaQY5eMuNjevpW9WaOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUvFypVql0k/nBFMqct8PqqlXeOcEwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/MAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABl/BatuEAAAQDAEcwRQIgHfTWqEtNiKJdIP3Hlx3jfpTlE5EKLrzQaDr8XNod/l8CIQCo41Lry0E0RgCk12NjzXLgI3fX90IMbjYOCi7qpJ1pojAKBggqhkjOPQQDAwNnADBkAjBDxtCzMBi9uGaYflFklkHb9gaI1AepSy9DxRuIegdsLnvtHNd3rLwbfPqJZOw4B4QCMb41oC+O1hO15qi1LtQVBmzkXLtWIy6youHR1ksJCMY9imNWVe+pUJQM/4lxvj7/qg==";

    auto cert_der_string = unfold::utils::Base64::decode(cert_der_base64);
    auto cert_result = Certificate::from_der(cert_der_string);

    ASSERT_TRUE(cert_result.has_value());
    auto &cert = cert_result.value();

    // Test vector<uint8_t> version with empty data (should fail but not crash)
    std::vector<uint8_t> empty_data;
    std::vector<uint8_t> empty_signature;
    auto result1 = cert.verify_signature(empty_data, empty_signature);
    EXPECT_TRUE(result1.has_value()); // Should return a bool result, even if false

    // Test string version with empty data (should fail but not crash)
    std::string empty_data_str;
    std::string empty_signature_str;
    auto result2 = cert.verify_signature(empty_data_str, empty_signature_str);
    EXPECT_TRUE(result2.has_value()); // Should return a bool result, even if false

    // Test with different digest algorithms
    auto result3 = cert.verify_signature(empty_data, empty_signature, DigestAlgorithm::SHA384);
    EXPECT_TRUE(result3.has_value());
  }

  TEST_F(CertificateTest, CertificateComparison)
  {
    // Test certificate created from DER
    std::string cert_base64 =
      "MIIC1TCCAlqgAwIBAgIUVyf2i/kSHHcUvZCiAGB2q+B39eMwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwNzEwMTgwNjA2WhcNMjUwNzEwMTgxNjA2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIZLdcmiYUHnyCmbyDODkt0TUS3hnUfD6hLLqWYKR0X48eL6aR7UsehluA0gYtNKypbJOLJdY/P94uKGZ1lvqbaOCAXkwggF1MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUWg8/Map8qWkIDlker4y1lyi8mEswHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wIwYDVR0RAQH/BBkwF4EVcm9iLmNhZWxlcnNAZ21haWwuY29tMCwGCisGAQQBg78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHWeQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAABl/WEIfUAAAQDAEcwRQIhANStMu8Ou4C2PHLIO6l5S0HZhdKVmIE9bTSobiOkjQBIAiATIbUPI8/xWAdKw3qTYvynwqTN1Ic4GSQZiMrnSy9P/jAKBggqhkjOPQQDAwNpADBmAjEAyLhTOg6lSrmMjX1HmcnbC/LSNJMBwugR3Vg1T5b81V5Ky3wLfDFM7pi4xRht4MONAjEAwEtFcEY1XfinR+mknwGt653egNEnUJmRK48UbplR9KmQ6/9iISMk50sX1JI2tlxP";

    std::string cert_der_str = unfold::utils::Base64::decode(cert_base64);
    std::vector<uint8_t> cert_der(cert_der_str.begin(), cert_der_str.end());

    // Create first certificate from DER
    auto cert1_result = Certificate::from_der(cert_der);
    ASSERT_TRUE(cert1_result.has_value());
    Certificate cert1 = std::move(cert1_result.value());

    // Create second certificate from DER (same data)
    auto cert2_result = Certificate::from_der(cert_der);
    ASSERT_TRUE(cert2_result.has_value());
    Certificate cert2 = std::move(cert2_result.value());

    // Test equality
    EXPECT_TRUE(cert1 == cert2);
    EXPECT_FALSE(cert1 != cert2);

    // Convert to PEM and create new certificate from PEM
    std::string pem_cert = "-----BEGIN CERTIFICATE-----\n";
    pem_cert += cert_base64 + "\n";
    pem_cert += "-----END CERTIFICATE-----";

    auto cert_pem_result = Certificate::from_pem(pem_cert);
    ASSERT_TRUE(cert_pem_result.has_value());
    Certificate cert_from_pem = std::move(cert_pem_result.value());

    // Test that certificate from PEM equals certificate from DER
    EXPECT_TRUE(cert1 == cert_from_pem);
    EXPECT_FALSE(cert1 != cert_from_pem);
  }

} // namespace unfold::sigstore::test
