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

#ifndef CERTIFICATE_HH
#define CERTIFICATE_HH

#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include <boost/outcome/std_result.hpp>
#include <spdlog/spdlog.h>
#include <openssl/x509.h>

#include "utils/Logging.hh"
#include "CryptographicAlgorithms.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  class PublicKey; // Forward declaration

  class Certificate
  {
  public:
    explicit Certificate(std::unique_ptr<X509, decltype(&X509_free)> x509_cert);
    Certificate() = delete;

    Certificate(Certificate &&other) noexcept = default;
    Certificate &operator=(Certificate &&other) noexcept = default;
    Certificate(const Certificate &) = delete;
    Certificate &operator=(const Certificate &) = delete;
    ~Certificate() = default;

    X509 *get() const;

    static outcome::std_result<Certificate> from_pem(const std::string &cert_pem);
    static outcome::std_result<Certificate> from_der(const std::vector<uint8_t> &cert_der);
    static outcome::std_result<Certificate> from_der(const std::string &cert_der);

    std::string subject_email() const;
    std::string oidc_issuer() const;
    bool is_self_signed() const;

    outcome::std_result<std::chrono::system_clock::time_point> get_not_before() const;
    outcome::std_result<std::chrono::system_clock::time_point> get_not_after() const;
    outcome::std_result<bool> is_valid_at_time(const std::chrono::system_clock::time_point &timestamp) const;

    outcome::std_result<PublicKey> get_public_key() const;

    outcome::std_result<bool> verify_signature(const std::vector<uint8_t> &data,
                                               const std::vector<uint8_t> &signature,
                                               DigestAlgorithm digest_algorithm = DigestAlgorithm::SHA256) const;

    outcome::std_result<bool> verify_signature(const std::string &data,
                                               const std::string &signature,
                                               DigestAlgorithm digest_algorithm = DigestAlgorithm::SHA256) const;

    bool operator==(const Certificate &other) const;
    bool operator!=(const Certificate &other) const;

  private:
    std::unique_ptr<X509, decltype(&X509_free)> x509_cert_{nullptr, X509_free};
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:certificate")};
  };

} // namespace unfold::sigstore

#endif // CERTIFICATE_HH
