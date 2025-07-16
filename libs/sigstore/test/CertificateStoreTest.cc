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

#include "CertificateStore.hh"
#include "Certificate.hh"
#include "utils/Base64.hh"

#include <gtest/gtest.h>
#include <gmock/gmock.h>

namespace
{
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays)
  const unsigned char embedded_trust_bundle[] = {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc23-extensions"
#embed "../src/trustBundle.json"
#pragma clang diagnostic pop
  };
  const size_t embedded_trust_bundle_size = sizeof(embedded_trust_bundle);

} // namespace

namespace unfold::sigstore::test
{
  class CertificateStoreTest : public ::testing::Test
  {
  public:
    std::unique_ptr<CertificateStore> &store()
    {
      return store_;
    }

  protected:
    void SetUp() override
    {
      store_ = std::make_unique<CertificateStore>();
    }

  private:
    std::unique_ptr<CertificateStore> store_;
  };

  TEST_F(CertificateStoreTest, InitialCertificateCountsAreZero)
  {
    EXPECT_EQ(store()->get_root_certificate_count(), 0);
    EXPECT_EQ(store()->get_intermediate_certificate_count(), 0);
  }

  TEST_F(CertificateStoreTest, LoadInvalidTrustBundle)
  {
    const std::string invalid_json = "{ invalid json }";
    auto result = store()->load_trust_bundle(invalid_json);
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(CertificateStoreTest, VerifyCertificateChainWithoutTrustBundle)
  {
    auto cert = Certificate::from_pem(unfold::utils::Base64::decode(
      "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMwekNDQWxxZ0F3SUJBZ0lVWUZQRk11MGNueWZPSHBNNm1SZUdtWVh2MGEwd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpVd056QTVNVGd3TWpRMldoY05NalV3TnpBNU1UZ3hNalEyV2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVYcXNHWVJaMUo4SHptclhqMVlRZ0ltQ2I5SUQ5U0xPd01QZjQKM1pORXFaOVg3aVMxSFd2WjQ2MThoNVFqSk5qbjcxMHFjWmFRWTVlTXVOamV2cFc5V2FPQ0FYa3dnZ0YxTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVV2RnlwClZxbDBrL25CRk1xY3Q4UHFxbFhlT2NFd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0l3WURWUjBSQVFIL0JCa3dGNEVWY205aUxtTmhaV3hsY25OQVoyMWhhV3d1WTI5dE1Dd0dDaXNHQVFRQgpnNzh3QVFFRUhtaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOXNiMmRwYmk5dllYVjBhREF1QmdvckJnRUVBWU8vCk1BRUlCQ0FNSG1oMGRIQnpPaTh2WjJsMGFIVmlMbU52YlM5c2IyZHBiaTl2WVhWMGFEQ0JpZ1lLS3dZQkJBSFcKZVFJRUFnUjhCSG9BZUFCMkFOMDlNR3JHeHhFeVl4a2VISmxuTndLaVNsNjQzanl0LzRlS2NvQXZLZTZPQUFBQgpsL0JhdHVFQUFBUURBRWN3UlFJZ0hmVFdxRXROaUtKZElQM0hseDNqZnBUbEU1RUtMcnpRYURyOFhOb2QvbDhDCklRQ080MUxyeTBFMFJnQ2sxMk5qelhMZ0kzZlg5MElNYmpZT0NpN3FwSjFwb2pBS0JnZ3Foa2pPUFFRREF3Tm4KQURCa0FqQkR4dEN6TUJpOXVHYVlmbEZrbGtIYjlnYUkxQWVwU3k5RHhSdUllZ2RzTG52dEhOZDNyTHdiZlBxSgpaT3c0QjRRQ01CNDFvQytPMWhPMTVxaTFMdFFWQm16a1hMdFdJeTZ5b3VIUjFrc0pDTVk5aW1OV1ZlK3BVSlFNCi80bHh2ajcvcWc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="));
    EXPECT_TRUE(cert.has_value());
    auto result = store()->verify_certificate_chain(cert.value());
    EXPECT_FALSE(result.has_value());
  }

  TEST_F(CertificateStoreTest, VerifyCertificateChainWithTrustBundle)
  {
    const auto *pem = R"(-----BEGIN CERTIFICATE-----
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
    auto cert = Certificate::from_pem(pem);

    // NOLINTNEXTLINE: Need to handle embedded binary data conversion
    std::string trust_bundle_json(reinterpret_cast<const char *>(embedded_trust_bundle), embedded_trust_bundle_size);
    auto certificate_store_res = store()->load_trust_bundle(trust_bundle_json);
    EXPECT_TRUE(certificate_store_res.has_value());
    EXPECT_EQ(store()->get_root_certificate_count(), 1);
    EXPECT_EQ(store()->get_intermediate_certificate_count(), 1);

    auto result = store()->verify_certificate_chain(cert.value());

    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
  }

} // namespace unfold::sigstore::test
