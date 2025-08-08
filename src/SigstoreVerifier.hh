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

#include <memory>
#include <string>
#include <boost/outcome/std_result.hpp>

#include "http/HttpClient.hh"
#include "sigstore/Context.hh"
#include "unfold/Unfold.hh"
#include "utils/Logging.hh"

namespace outcome = boost::outcome_v2;

class SigstoreVerifier
{
public:
  explicit SigstoreVerifier(std::shared_ptr<sigstore::Context> context, std::shared_ptr<unfold::http::HttpClient> http);
  virtual ~SigstoreVerifier() = default;

  virtual void set_verification_enabled(bool enabled);
  virtual void set_validation_callback(unfold::Unfold::sigstore_validation_callback_t callback);

  virtual boost::asio::awaitable<outcome::std_result<void>> verify(std::string url, std::string data);
  virtual boost::asio::awaitable<outcome::std_result<void>> verify(std::string url, std::filesystem::path filename);

private:
  boost::asio::awaitable<outcome::std_result<std::shared_ptr<sigstore::Bundle>>> download_sigstore_bundle(std::string url);
  outcome::std_result<void> verify_sigstore(std::shared_ptr<sigstore::Bundle> sigstore_bundle, std::string data);
  outcome::std_result<void> verify_sigstore(std::shared_ptr<sigstore::Bundle> sigstore_bundle, std::filesystem::path filename);

private:
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:sigstore")};
  std::shared_ptr<sigstore::Context> context;
  std::shared_ptr<unfold::http::HttpClient> http;
  bool verification_enabled{false};
  unfold::Unfold::sigstore_validation_callback_t validation_callback;
};

#endif // SIGSTORE_VERIFIER_HH
