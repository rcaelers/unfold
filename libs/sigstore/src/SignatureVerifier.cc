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

#include "SignatureVerifier.hh"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <bit>

#include "sigstore/SigstoreErrors.hh"
#include "utils/Base64.hh"
#include "Certificate.hh"

namespace unfold::sigstore
{

  SignatureVerifier::SignatureVerifier() = default;
  SignatureVerifier::~SignatureVerifier() = default;
  SignatureVerifier::SignatureVerifier(SignatureVerifier &&) noexcept = default;
  SignatureVerifier &SignatureVerifier::operator=(SignatureVerifier &&) noexcept = default;

  outcome::std_result<bool> SignatureVerifier::verify_signature(std::string_view content,
                                                                const Certificate &certificate,
                                                                const std::string &signature)
  {
    std::string signature_bytes;
    try
      {
        signature_bytes = unfold::utils::Base64::decode(signature);
      }
    catch (const std::exception &e)
      {
        logger_->error("Failed to decode signature: {}", e.what());
        return SigstoreError::InvalidSignature;
      }

    return verify_signature_with_public_key(content, signature_bytes, certificate.get());
  }

  outcome::std_result<bool> SignatureVerifier::verify_signature_with_public_key(std::string_view content,
                                                                                const std::string &signature_bytes,
                                                                                X509 *cert)
  {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(X509_get_pubkey(cert), EVP_PKEY_free);
    if (!pkey)
      {
        logger_->error("Failed to extract public key from certificate");
        return SigstoreError::InvalidCertificate;
      }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!md_ctx)
      {
        logger_->error("Failed to create MD context");
        return SigstoreError::SystemError;
      }

    int verify_result = 0;
    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) == 1)
      {
        const auto *sig_data = std::bit_cast<const unsigned char *>(signature_bytes.data());
        const auto *content_data = std::bit_cast<const unsigned char *>(content.data());
        verify_result = EVP_DigestVerify(md_ctx.get(), sig_data, signature_bytes.size(), content_data, content.size());
      }

    bool signature_valid = (verify_result == 1);
    return signature_valid;
  }

} // namespace unfold::sigstore
