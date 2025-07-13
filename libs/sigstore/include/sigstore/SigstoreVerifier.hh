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

#ifndef SIGSTORE_VERIFIER_HH
#define SIGSTORE_VERIFIER_HH

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <chrono>
#include <boost/outcome/std_result.hpp>
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "http/HttpClient.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  struct SigstoreVerificationResult
  {
    bool is_valid{false};
    bool signature_valid{false};
    bool certificate_valid{false};
    bool fulcio_chain_valid{false};
    bool transparency_log_valid{false};
    std::string subject_email;
    std::string issuer;
    std::string oidc_issuer;
    std::chrono::system_clock::time_point signed_at;
    std::vector<std::string> errors;
  };

  class SigstoreVerifier
  {
  public:
    explicit SigstoreVerifier(std::shared_ptr<unfold::http::IHttpClient> http_client);
    ~SigstoreVerifier();

    SigstoreVerifier(const SigstoreVerifier &) = delete;
    SigstoreVerifier &operator=(const SigstoreVerifier &) = delete;
    SigstoreVerifier(SigstoreVerifier &&) noexcept;
    SigstoreVerifier &operator=(SigstoreVerifier &&) noexcept;

    boost::asio::awaitable<outcome::std_result<bool>> verify(std::string_view data, std::string_view bundle_json);

    outcome::std_result<void> set_rekor_public_key(const std::string &public_key_pem);
    boost::asio::awaitable<outcome::std_result<void>> download_fulcio_ca_certificates();

  private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
  };

} // namespace unfold::sigstore

#endif // SIGSTORE_VERIFIER_HH
