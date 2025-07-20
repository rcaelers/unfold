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

#include "PublicKey.hh"

#include <cstring>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "sigstore/SigstoreErrors.hh"
#include "CryptographicAlgorithms.hh"

namespace unfold::sigstore
{
  PublicKey::PublicKey(std::unique_ptr<EVP_PKEY, EVPKeyDeleter> evp_key)
    : evp_key_(std::move(evp_key))
  {
  }

  outcome::std_result<PublicKey> PublicKey::from_pem(const std::string &key_pem)
  {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(key_pem.c_str(), -1), BIO_free);
    if (!bio)
      {
        return SigstoreError::InvalidPublicKey;
      }

    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (key == nullptr)
      {
        return SigstoreError::InvalidPublicKey;
      }

    return PublicKey(std::unique_ptr<EVP_PKEY, EVPKeyDeleter>(key));
  }

  outcome::std_result<PublicKey> PublicKey::from_der(const std::vector<uint8_t> &key_der)
  {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(key_der.data(), static_cast<int>(key_der.size())), BIO_free);
    if (!bio)
      {
        return SigstoreError::InvalidPublicKey;
      }

    EVP_PKEY *key = d2i_PUBKEY_bio(bio.get(), nullptr);
    if (key == nullptr)
      {
        return SigstoreError::InvalidPublicKey;
      }

    return PublicKey(std::unique_ptr<EVP_PKEY, EVPKeyDeleter>(key));
  }

  outcome::std_result<PublicKey> PublicKey::from_der(const std::string &key_der)
  {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(key_der.data(), static_cast<int>(key_der.size())), BIO_free);
    if (!bio)
      {
        return SigstoreError::InvalidPublicKey;
      }

    EVP_PKEY *key = d2i_PUBKEY_bio(bio.get(), nullptr);
    if (key == nullptr)
      {
        return SigstoreError::InvalidPublicKey;
      }

    return PublicKey(std::unique_ptr<EVP_PKEY, EVPKeyDeleter>(key));
  }

  outcome::std_result<PublicKey> PublicKey::from_certificate(const std::string &cert_pem)
  {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(cert_pem.c_str(), -1), BIO_free);
    if (!bio)
      {
        return SigstoreError::InvalidCertificate;
      }

    std::unique_ptr<X509, decltype(&X509_free)> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
    if (!cert)
      {
        return SigstoreError::InvalidCertificate;
      }

    EVP_PKEY *key = X509_get_pubkey(cert.get());
    if (key == nullptr)
      {
        return SigstoreError::InvalidPublicKey;
      }

    return PublicKey(std::unique_ptr<EVP_PKEY, EVPKeyDeleter>(key));
  }

  outcome::std_result<PublicKey> PublicKey::from_evp_key(EVP_PKEY *evp_key)
  {
    if (evp_key == nullptr)
      {
        return SigstoreError::InvalidPublicKey;
      }

    return PublicKey(std::unique_ptr<EVP_PKEY, EVPKeyDeleter>(evp_key));
  }

  EVP_PKEY *PublicKey::get() const
  {
    return evp_key_.get();
  }

  KeyAlgorithm PublicKey::get_algorithm() const
  {
    if (!evp_key_)
      {
        return KeyAlgorithm::Unknown;
      }

    int key_type = EVP_PKEY_id(evp_key_.get());
    switch (key_type)
      {
      case EVP_PKEY_RSA:
        return KeyAlgorithm::RSA;
      case EVP_PKEY_EC:
        return KeyAlgorithm::ECDSA;
      case EVP_PKEY_ED25519:
      case EVP_PKEY_ED448:
        return KeyAlgorithm::EdDSA;
      default:
        return KeyAlgorithm::Unknown;
      }
  }

  int PublicKey::get_key_size_bits() const
  {
    if (!evp_key_)
      {
        return -1;
      }

    constexpr int BITS_PER_BYTE = 8;
    return EVP_PKEY_get_size(evp_key_.get()) * BITS_PER_BYTE;
  }

  std::string PublicKey::get_algorithm_name() const
  {
    switch (get_algorithm())
      {
      case KeyAlgorithm::RSA:
        return "RSA";
      case KeyAlgorithm::ECDSA:
        return "ECDSA";
      case KeyAlgorithm::EdDSA:
        return "EdDSA";
      case KeyAlgorithm::Unknown:
      default:
        return "Unknown";
      }
  }

  outcome::std_result<bool> PublicKey::verify_signature(const std::vector<uint8_t> &data,
                                                        const std::vector<uint8_t> &signature,
                                                        DigestAlgorithm digest_algorithm) const
  {
    if (!evp_key_)
      {
        logger_->error("Cannot verify signature: no public key loaded");
        return SigstoreError::InvalidPublicKey;
      }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
      {
        logger_->error("Failed to create EVP_MD_CTX");
        return SigstoreError::SystemError;
      }

    const EVP_MD *md = nullptr;
    switch (digest_algorithm)
      {
      case DigestAlgorithm::SHA256:
        md = EVP_sha256();
        break;
      case DigestAlgorithm::SHA384:
        md = EVP_sha384();
        break;
      case DigestAlgorithm::SHA512:
        md = EVP_sha512();
        break;
      case DigestAlgorithm::SHA1:
        md = EVP_sha1();
        break;
      default:
        logger_->error("Unsupported digest algorithm");
        return SigstoreError::InvalidSignature;
      }

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, evp_key_.get()) != 1)
      {
        logger_->error("Failed to initialize digest verification");
        return SigstoreError::SystemError;
      }

    if (EVP_DigestVerifyUpdate(ctx.get(), data.data(), data.size()) != 1)
      {
        logger_->error("Failed to update digest verification with data");
        return SigstoreError::SystemError;
      }

    int result = EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size());
    if (result == 1)
      {
        logger_->debug("Signature verification successful");
        return true;
      }
    if (result == 0)
      {
        logger_->debug("Signature verification failed: signature does not match");
        return false;
      }

    logger_->error("Signature verification failed with error: {} {}", result, ERR_error_string(ERR_get_error(), nullptr));
    return SigstoreError::SystemError;
  }

  outcome::std_result<bool> PublicKey::verify_signature(const std::string &data,
                                                        const std::string &signature,
                                                        DigestAlgorithm digest_algorithm) const
  {
    std::vector<uint8_t> data_bytes(data.begin(), data.end());
    std::vector<uint8_t> sig_bytes(signature.begin(), signature.end());
    return verify_signature(data_bytes, sig_bytes, digest_algorithm);
  }

} // namespace unfold::sigstore
