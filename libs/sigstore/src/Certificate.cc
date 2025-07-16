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

#include <chrono>
#include <ctime>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>

#include "sigstore/SigstoreErrors.hh"
#include "PublicKey.hh"

namespace unfold::sigstore
{
  Certificate::Certificate(std::unique_ptr<X509, decltype(&X509_free)> x509_cert)
    : x509_cert_(std::move(x509_cert))
  {
  }

  X509 *Certificate::get() const
  {
    return x509_cert_.get();
  }

  outcome::std_result<Certificate> Certificate::from_pem(const std::string &cert_pem)
  {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(cert_pem.c_str(), -1), BIO_free);
    if (!bio)
      {
        return SigstoreError::InvalidCertificate;
      }

    X509 *cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (cert == nullptr)
      {
        return SigstoreError::InvalidCertificate;
      }
    return Certificate(std::unique_ptr<X509, decltype(&X509_free)>(cert, X509_free));
  }

  outcome::std_result<Certificate> Certificate::from_der(const std::vector<uint8_t> &cert_der)
  {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(cert_der.data(), static_cast<int>(cert_der.size())), BIO_free);
    if (!bio)
      {
        return SigstoreError::InvalidCertificate;
      }

    X509 *cert = d2i_X509_bio(bio.get(), nullptr);
    if (cert == nullptr)
      {
        return SigstoreError::InvalidCertificate;
      }
    return Certificate(std::unique_ptr<X509, decltype(&X509_free)>(cert, X509_free));
  }

  outcome::std_result<Certificate> Certificate::from_der(const std::string &cert_der)
  {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(cert_der.data(), static_cast<int>(cert_der.size())), BIO_free);
    if (!bio)
      {
        return SigstoreError::InvalidCertificate;
      }

    X509 *cert = d2i_X509_bio(bio.get(), nullptr);
    if (cert == nullptr)
      {
        return SigstoreError::InvalidCertificate;
      }
    return Certificate(std::unique_ptr<X509, decltype(&X509_free)>(cert, X509_free));
  }

  bool Certificate::is_self_signed() const
  {
    X509 *cert = get();

    X509_NAME *issuer = X509_get_issuer_name(cert);
    X509_NAME *subject = X509_get_subject_name(cert);

    if (issuer == nullptr || subject == nullptr)
      {
        return false;
      }

    int cmp_result = X509_NAME_cmp(issuer, subject);
    if (cmp_result != 0)
      {
        return false;
      }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(X509_get_pubkey(cert), EVP_PKEY_free);
    if (!pkey)
      {
        return false;
      }

    int verify_result = X509_verify(cert, pkey.get());
    return verify_result == 1;
  }

  std::string Certificate::subject_email() const
  {
    X509 *cert = get();

    STACK_OF(GENERAL_NAME) *san_names = static_cast<STACK_OF(GENERAL_NAME) *>(
      X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));

    if (san_names == nullptr)
      {
        return "";
      }

    std::string email;
    int san_count = sk_GENERAL_NAME_num(san_names);

    for (int i = 0; i < san_count; i++)
      {
        GENERAL_NAME *san = sk_GENERAL_NAME_value(san_names, i);
        if (san != nullptr && san->type == GEN_EMAIL)
          {
            // NOLINTNEXTLINE: OpenSSL API
            ASN1_STRING *email_str = san->d.ia5;
            if (email_str != nullptr)
              {
                const unsigned char *data = ASN1_STRING_get0_data(email_str);
                if (data != nullptr)
                  {
                    int len = ASN1_STRING_length(email_str);
                    // NOLINTNEXTLINE: OpenSSL API requires binary data conversion
                    email = std::string(reinterpret_cast<const char *>(data), len);
                    break;
                  }
              }
          }
      }

    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    return email;
  }

  std::string Certificate::oidc_issuer() const
  {
    X509 *cert = get();

    ASN1_OBJECT *oid = OBJ_txt2obj("1.3.6.1.4.1.57264.1.1", 1);
    if (oid == nullptr)
      {
        logger_->error("Failed to create OID object for OIDC issuer extension");
        return "";
      }

    int ext_idx = X509_get_ext_by_OBJ(cert, oid, -1);
    ASN1_OBJECT_free(oid);

    if (ext_idx < 0)
      {
        logger_->error("OIDC issuer extension not found in certificate");
        return "";
      }

    X509_EXTENSION *ext = X509_get_ext(cert, ext_idx);
    if (ext == nullptr)
      {
        logger_->error("Failed to get OIDC issuer extension from certificate");
        return "";
      }

    ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
    if (ext_data == nullptr)
      {
        logger_->error("Failed to get OIDC issuer extension data");
        return "";
      }

    const unsigned char *data = ASN1_STRING_get0_data(ext_data);
    int len = ASN1_STRING_length(ext_data);

    // NOLINTNEXTLINE: OpenSSL API requires binary data conversion
    std::string issuer = std::string(reinterpret_cast<const char *>(data), len);
    return issuer;
  }

  outcome::std_result<std::chrono::system_clock::time_point> Certificate::get_not_before() const
  {
    X509 *cert = get();
    if (cert == nullptr)
      {
        logger_->error("Certificate is null");
        return SigstoreError::InvalidCertificate;
      }

    const ASN1_TIME *not_before = X509_get0_notBefore(cert);
    if (not_before == nullptr)
      {
        logger_->error("Certificate has no notBefore time");
        return SigstoreError::InvalidCertificate;
      }

    struct tm tm_time = {};
    if (ASN1_TIME_to_tm(not_before, &tm_time) != 1)
      {
        logger_->error("Failed to convert certificate notBefore time");
        return SigstoreError::InvalidCertificate;
      }

    std::time_t time_t_value = std::mktime(&tm_time);
    return std::chrono::system_clock::from_time_t(time_t_value);
  }

  outcome::std_result<std::chrono::system_clock::time_point> Certificate::get_not_after() const
  {
    X509 *cert = get();
    if (cert == nullptr)
      {
        logger_->error("Certificate is null");
        return SigstoreError::InvalidCertificate;
      }

    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    if (not_after == nullptr)
      {
        logger_->error("Certificate has no notAfter time");
        return SigstoreError::InvalidCertificate;
      }

    struct tm tm_time = {};
    if (ASN1_TIME_to_tm(not_after, &tm_time) != 1)
      {
        logger_->error("Failed to convert certificate notAfter time");
        return SigstoreError::InvalidCertificate;
      }

    std::time_t time_t_value = std::mktime(&tm_time);
    return std::chrono::system_clock::from_time_t(time_t_value);
  }

  outcome::std_result<bool> Certificate::is_valid_at_time(const std::chrono::system_clock::time_point &timestamp) const
  {
    auto not_before_result = get_not_before();
    auto not_after_result = get_not_after();

    if (!not_before_result.has_value())
      {
        logger_->error("Failed to get certificate notBefore time: {}", not_before_result.error().message());
        return not_before_result.error();
      }
    if (!not_after_result.has_value())
      {
        logger_->error("Failed to get certificate notAfter time: {}", not_after_result.error().message());
        return not_after_result.error();
      }

    auto not_before = not_before_result.value();
    auto not_after = not_after_result.value();

    bool valid = (timestamp >= not_before && timestamp <= not_after);

    if (!valid)
      {
        logger_->debug("Certificate not valid at timestamp {}: valid from {} to {}", timestamp, not_before, not_after);
      }

    return valid;
  }

  outcome::std_result<PublicKey> Certificate::get_public_key() const
  {
    if (!x509_cert_)
      {
        logger_->error("Cannot extract public key: no certificate loaded");
        return SigstoreError::InvalidCertificate;
      }

    EVP_PKEY *pkey = X509_get_pubkey(x509_cert_.get());
    if (pkey == nullptr)
      {
        logger_->error("Failed to extract public key from certificate");
        return SigstoreError::InvalidCertificate;
      }

    return PublicKey::from_evp_key(pkey);
  }

  outcome::std_result<bool> Certificate::verify_signature(const std::vector<uint8_t> &data,
                                                          const std::vector<uint8_t> &signature,
                                                          DigestAlgorithm digest_algorithm) const
  {
    auto public_key_result = get_public_key();
    if (!public_key_result)
      {
        return public_key_result.error();
      }

    return public_key_result.value().verify_signature(data, signature, digest_algorithm);
  }

  outcome::std_result<bool> Certificate::verify_signature(const std::string &data,
                                                          const std::string &signature,
                                                          DigestAlgorithm digest_algorithm) const
  {
    auto public_key_result = get_public_key();
    if (!public_key_result)
      {
        return public_key_result.error();
      }

    return public_key_result.value().verify_signature(data, signature, digest_algorithm);
  }

} // namespace unfold::sigstore
