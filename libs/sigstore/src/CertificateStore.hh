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

#ifndef CERTIFICATE_STORE_HH
#define CERTIFICATE_STORE_HH

#include <boost/json.hpp>
#include <string>
#include <vector>
#include <memory>
#include <boost/json/array.hpp>
#include <boost/outcome/std_result.hpp>
#include <openssl/x509.h>
#include <spdlog/spdlog.h>

#include "Certificate.hh"
#include "utils/Logging.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  class CertificateStore
  {
  public:
    CertificateStore() = default;
    ~CertificateStore() = default;

    CertificateStore(const CertificateStore &) = delete;
    CertificateStore &operator=(const CertificateStore &) = delete;
    CertificateStore(CertificateStore &&) noexcept = default;
    CertificateStore &operator=(CertificateStore &&) noexcept = default;

    outcome::std_result<void> load_trust_bundle(const std::string &trust_bundle_json);
    outcome::std_result<bool> verify_certificate_chain(const Certificate &cert);

    size_t get_root_certificate_count() const;
    size_t get_intermediate_certificate_count() const;

  private:
    outcome::std_result<void> load_chain(const boost::json::value &chain,
                                         std::vector<Certificate> &intermediate_certificates,
                                         std::vector<Certificate> &root_certificates);
    outcome::std_result<void> init_root_store();
    void log_validated_chain(X509_STORE_CTX *cert_ctx);

  private:
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:certificatestore")};
    std::vector<Certificate> intermediate_certificates_;
    std::vector<Certificate> root_certificates_;
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> root_store_{nullptr, X509_STORE_free};
  };

} // namespace unfold::sigstore

#endif // CERTIFICATE_STORE_HH
