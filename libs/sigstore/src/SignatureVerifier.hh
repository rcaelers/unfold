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

#ifndef SIGNATURE_VERIFIER_HH
#define SIGNATURE_VERIFIER_HH

#include <string>
#include <string_view>
#include <memory>
#include <boost/outcome/std_result.hpp>
#include <openssl/x509.h>
#include <spdlog/spdlog.h>

#include "utils/Logging.hh"
#include "Certificate.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  class CertificateStore;

  class SignatureVerifier
  {
  public:
    explicit SignatureVerifier();
    ~SignatureVerifier();

    SignatureVerifier(const SignatureVerifier &) = delete;
    SignatureVerifier &operator=(const SignatureVerifier &) = delete;
    SignatureVerifier(SignatureVerifier &&) noexcept;
    SignatureVerifier &operator=(SignatureVerifier &&) noexcept;

    outcome::std_result<bool> verify_signature(std::string_view content,
                                               const Certificate &certificate,
                                               const std::string &signature);

  private:
    outcome::std_result<bool> verify_signature_with_public_key(std::string_view content,
                                                               const std::string &signature_bytes,
                                                               X509 *cert);

    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:signature")};
  };

} // namespace unfold::sigstore

#endif // SIGNATURE_VERIFIER_HH
