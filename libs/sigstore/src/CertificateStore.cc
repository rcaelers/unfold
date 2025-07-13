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

#include <boost/json/array.hpp>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <boost/json.hpp>

#include "Certificate.hh"
#include "sigstore/SigstoreErrors.hh"

namespace unfold::sigstore
{

  outcome::std_result<void> CertificateStore::load_trust_bundle(const std::string &trust_bundle_json)
  {
    try
      {
        boost::json::value json_val = boost::json::parse(trust_bundle_json);

        if (!json_val.is_object())
          {
            logger_->error("Trust bundle is not a valid JSON object");
            return SigstoreError::JsonParseError;
          }

        const auto &obj = json_val.as_object();
        if (!obj.contains("chains") || !obj.at("chains").is_array())
          {
            logger_->error("Trust bundle does not contain chains array");
            return SigstoreError::JsonParseError;
          }

        const auto &chains = obj.at("chains").as_array();
        if (chains.empty())
          {
            logger_->error("Trust bundle chains array is empty");
            return SigstoreError::JsonParseError;
          }

        std::vector<Certificate> intermediate_certificates;
        std::vector<Certificate> root_certificates;
        for (const auto &chain: chains)
          {
            auto result = load_chain(chain, intermediate_certificates, root_certificates);
            if (!result)
              {
                logger_->error("Failed to load chain: {}", result.error().message());
                return result;
              }
          }

        if (root_certificates.empty())
          {
            logger_->error("No valid root certificates found in trust bundle");
            return SigstoreError::InvalidCertificate;
          }

        intermediate_certificates_ = std::move(intermediate_certificates);
        root_certificates_ = std::move(root_certificates);
        return init_root_store();
      }
    catch (const std::exception &e)
      {
        logger_->error("Failed to parse trust bundle: {}", e.what());
        return SigstoreError::JsonParseError;
      }
  }

  outcome::std_result<void> CertificateStore::load_chain(const boost::json::value &chain,
                                                         std::vector<Certificate> &intermediate_certificates,
                                                         std::vector<Certificate> &root_certificates)
  {
    if (!chain.is_object())
      {
        logger_->error("Skipping invalid chain object");
        return SigstoreError::JsonParseError;
      }

    const auto &chain_obj = chain.as_object();
    if (!chain_obj.contains("certificates") || !chain_obj.at("certificates").is_array())
      {
        logger_->error("Chain does not contain certificates array");
        return SigstoreError::JsonParseError;
      }

    const auto &certificates = chain_obj.at("certificates").as_array();
    if (certificates.empty())
      {
        logger_->error("Certificates array is empty in chain");
        return SigstoreError::JsonParseError;
      }

    for (size_t i = 0; i < certificates.size(); ++i)
      {
        const auto &cert_str = certificates[i];
        if (!cert_str.is_string())
          {
            logger_->warn("Certificate is not a string,");
            return SigstoreError::JsonParseError;
          }

        std::string cert_pem = std::string(cert_str.as_string());
        auto cert_result = Certificate::from_pem(cert_pem);
        if (!cert_result)
          {
            logger_->warn("Invalid certificate in trust bundle");
            return SigstoreError::JsonParseError;
          }
        auto &cert = cert_result.value();

        bool is_root_ca = (i == certificates.size() - 1) || cert.is_self_signed();

        if (is_root_ca)
          {
            root_certificates.emplace_back(std::move(cert));
          }
        else
          {
            intermediate_certificates.emplace_back(std::move(cert));
          }
      }
    return outcome::success();
  }

  outcome::std_result<void> CertificateStore::init_root_store()
  {
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(X509_STORE_new(), X509_STORE_free);
    if (!store)
      {
        logger_->error("Failed to create certificate store");
        return SigstoreError::SystemError;
      }
    X509_STORE_set_flags(store.get(), X509_V_FLAG_NO_CHECK_TIME);

    for (const auto &root_cert: root_certificates_)
      {
        if (X509_STORE_add_cert(store.get(), root_cert.get()) != 1)
          {
            logger_->warn("Failed to add root certificate to store, may be duplicate");
          }
      }
    root_store_ = std::move(store);
    return outcome::success();
  }

  outcome::std_result<bool> CertificateStore::verify_certificate_chain(const Certificate &cert)
  {
    logger_->info("Verifying certificate chain");
    if (!root_store_)
      {
        logger_->error("Root store is not initialized");
        return SigstoreError::SystemError;
      }

    std::unique_ptr<STACK_OF(X509), void (*)(STACK_OF(X509) *)> untrusted(sk_X509_new_null(), [](STACK_OF(X509) * sk) {
      sk_X509_pop_free(sk, X509_free);
    });

    if (!untrusted)
      {
        logger_->error("Failed to create certificate stack for chain");
        return SigstoreError::SystemError;
      }

    for (const auto &intermediate_cert: intermediate_certificates_)
      {
        X509_up_ref(intermediate_cert.get());
        if (sk_X509_push(untrusted.get(), intermediate_cert.get()) <= 0)
          {
            logger_->warn("Failed to add intermediate certificate to stack");
            X509_free(intermediate_cert.get());
            break;
          }
      }

    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (!ctx)
      {
        logger_->error("Failed to create verification context");
        return SigstoreError::SystemError;
      }

    if (X509_STORE_CTX_init(ctx.get(), root_store_.get(), cert.get(), untrusted.get()) != 1)
      {
        logger_->error("Failed to initialize verification context");
        return SigstoreError::SystemError;
      }

    int verify_result = X509_verify_cert(ctx.get());

    if (verify_result == 1)
      {
        log_validated_chain(ctx.get());
        return true;
      }

    int error = X509_STORE_CTX_get_error(ctx.get());
    const char *error_string = X509_verify_cert_error_string(error);
    logger_->debug("Certificate chain verification failed: {}", error_string);

    return false;
  }

  void CertificateStore::log_validated_chain(X509_STORE_CTX *cert_ctx)
  {
    auto *chain = X509_STORE_CTX_get1_chain(cert_ctx);
    if (chain != nullptr)
      {
        if (sk_X509_num(chain) == 0)
          {
            logger_->debug("No chain found.");
            return;
          }
        for (int i = 0; i < sk_X509_num(chain); ++i)
          {
            X509 *cert = sk_X509_value(chain, i);
            char *subject = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
            char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
            logger_->debug("  Cert {}:", i);
            logger_->debug("    Subject: {}", subject);
            logger_->debug("    Issuer: {}", issuer);
            OPENSSL_free(subject);
            OPENSSL_free(issuer);
          }
        logger_->debug("--------------------------");
      }
    else
      {
        logger_->debug("No chain found in certificate context.");
      }
  }

  size_t CertificateStore::get_root_certificate_count() const
  {
    return root_certificates_.size();
  }

  size_t CertificateStore::get_intermediate_certificate_count() const
  {
    return intermediate_certificates_.size();
  }

} // namespace unfold::sigstore
