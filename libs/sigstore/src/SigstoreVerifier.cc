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

#include "sigstore/SigstoreVerifier.hh"

#include "BundleHelper.hh"
#include "BundleLoader.hh"
#include "TransparencyLogVerifier.hh"
#include "CertificateStore.hh"

#include <memory>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "utils/Logging.hh"
#include "utils/Base64.hh"
#include "http/HttpClient.hh"
#include "sigstore/SigstoreErrors.hh"

#include "sigstore_bundle.pb.h"

namespace
{
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays)
  const unsigned char embedded_trust_bundle[] = {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc23-extensions"
#embed "trustBundle.json"
#pragma clang diagnostic pop
  };
  const size_t embedded_trust_bundle_size = sizeof(embedded_trust_bundle);

} // namespace

namespace unfold::sigstore
{

  class SigstoreVerifier::Impl
  {
  public:
    explicit Impl(std::shared_ptr<unfold::http::IHttpClient> http_client)
      : http_client_(http_client)
      , transparency_log_verifier_(std::make_unique<TransparencyLogVerifier>())
      , logger_(unfold::utils::Logging::create("unfold:sigstore"))
      , certificate_store_(std::make_shared<CertificateStore>())
    {
      auto res = load_embedded_fulcio_ca_certificates();
      if (!res)
        {
          logger_->error("Failed to load embedded Fulcio CA certificates");
        }
      else
        {
          logger_->debug("Embedded Fulcio CA certificates loaded successfully");
        }
    }

  public:
    outcome::std_result<dev::sigstore::bundle::v1::Bundle> parse_bundle(const std::string &bundle_json)
    {
      SigstoreBundleLoader loader;
      auto bundle_result = loader.load_from_json(bundle_json);
      if (!bundle_result)
        {
          logger_->error("Failed to parse sigstore bundle: {}", bundle_result.error().message());
          return bundle_result.error();
        }
      return bundle_result.value();
    }

    outcome::std_result<bool> verify_signature(const std::string_view &content, const dev::sigstore::bundle::v1::Bundle &bundle)
    {
      BundleHelper helper(bundle);
      auto certificate = helper.get_certificate();
      const auto &signature = helper.get_signature();

      std::vector<uint8_t> signature_bytes;
      signature_bytes.assign(signature.begin(), signature.end());

      std::vector<uint8_t> content_bytes(content.begin(), content.end());
      return certificate->verify_signature(content_bytes, signature_bytes);
    }

    outcome::std_result<bool> verify_certificate_chain(const dev::sigstore::bundle::v1::Bundle &bundle)
    {
      BundleHelper helper(bundle);
      auto cert = helper.get_certificate();
      return certificate_store_->verify_certificate_chain(*cert);
    }

    boost::asio::awaitable<outcome::std_result<bool>> verify(std::string_view data, std::string_view bundle_json)
    {
      std::string bundle_str(bundle_json);

      auto bundle_result = parse_bundle(bundle_str);
      if (!bundle_result)
        {
          logger_->error("Failed to parse sigstore bundle");
          co_return bundle_result.error();
        }

      auto bundle = bundle_result.value();

      auto verify_result = verify_signature(data, bundle);
      if (!verify_result)
        {
          logger_->error("Signature verification failed");
          co_return verify_result.error();
        }
      if (!verify_result.value())
        {
          logger_->warn("Signature verification failed: signature does not match");
        }

      auto chain_result = verify_certificate_chain(bundle);
      if (!chain_result)
        {
          logger_->error("Certificate chain verification failed");
          co_return chain_result.error();
        }

      if (!chain_result.value())
        {
          logger_->warn("Certificate chain verification failed: chain is not valid");
        }

      outcome::std_result<void> log_result = outcome::success();

      // TODO: Add transparency log verification once get_transparency_log_entries is implemented
      // For now, we'll skip transparency log verification for the new SigstoreBundle format

      if (!log_result)
        {
          logger_->error("Transparency log verification failed: {}", log_result.error().message());
        }

      auto is_valid = verify_result.value() && chain_result.value() && log_result.has_value() && log_result;

      if (is_valid)
        {
          logger_->info("Sigstore verification successful");
        }
      else
        {
          logger_->warn("Sigstore verification failed");
        }

      co_return is_valid;
    }

    outcome::std_result<void> load_embedded_fulcio_ca_certificates()
    {
      logger_->debug("Loading embedded Fulcio CA certificates using CertificateStore");

      // NOLINTNEXTLINE: Need to handle embedded binary data conversion
      std::string trust_bundle_json(reinterpret_cast<const char *>(embedded_trust_bundle), embedded_trust_bundle_size);

      auto certificate_store_res = certificate_store_->load_trust_bundle(trust_bundle_json);
      if (!certificate_store_res)
        {
          logger_->error("Failed to load embedded Fulcio CA certificates: {}", certificate_store_res.error().message());
          return certificate_store_res.error();
        }

      return outcome::success();
    }

    boost::asio::awaitable<outcome::std_result<void>> download_fulcio_ca_certificates()
    {
      try
        {
          const std::string trust_bundle_url = "https://tuf-repo-cdn.sigstore.dev/targets/trusted_root.json";

          auto rc = co_await http_client_->get(trust_bundle_url);

          if (!rc)
            {
              logger_->warn("Failed to download trust bundle from {}: {}, using embedded certificates", trust_bundle_url, rc.error().message());
              co_return load_embedded_fulcio_ca_certificates();
            }

          auto [status_code, response_body] = rc.value();

          constexpr int HTTP_OK = 200;
          if (status_code != HTTP_OK)
            {
              logger_->warn("HTTP error {} when downloading trust bundle from {}, using embedded certificates", status_code, trust_bundle_url);
              co_return load_embedded_fulcio_ca_certificates();
            }

          logger_->info("Successfully downloaded trust bundle from {}", trust_bundle_url);
          auto certificate_store_res = certificate_store_->load_trust_bundle(response_body);
          if (!certificate_store_res)
            {
              logger_->error("Failed to load embedded Fulcio CA certificates: {}", certificate_store_res.error().message());
              co_return certificate_store_res.error();
            }

          co_return outcome::success();
        }
      catch (const std::exception &e)
        {
          logger_->warn("Exception while downloading trust bundle: {}, using embedded certificates", e.what());
          co_return load_embedded_fulcio_ca_certificates();
        }
    }

    // ...existing code...

  private:
    std::shared_ptr<unfold::http::IHttpClient> http_client_;
    std::unique_ptr<TransparencyLogVerifier> transparency_log_verifier_;
    std::shared_ptr<spdlog::logger> logger_;
    std::shared_ptr<CertificateStore> certificate_store_;
    std::string rekor_public_key_;
  };

  SigstoreVerifier::SigstoreVerifier(std::shared_ptr<unfold::http::IHttpClient> http_client)
    : pimpl(std::make_unique<Impl>(std::move(http_client)))
  {
  }

  SigstoreVerifier::~SigstoreVerifier() = default;
  SigstoreVerifier::SigstoreVerifier(SigstoreVerifier &&) noexcept = default;
  SigstoreVerifier &SigstoreVerifier::operator=(SigstoreVerifier &&) noexcept = default;

  boost::asio::awaitable<outcome::std_result<bool>> SigstoreVerifier::verify(std::string_view data, std::string_view bundle_json)
  {
    co_return co_await pimpl->verify(data, bundle_json);
  }

  boost::asio::awaitable<outcome::std_result<void>> SigstoreVerifier::download_fulcio_ca_certificates()
  {
    co_return co_await pimpl->download_fulcio_ca_certificates();
  }

} // namespace unfold::sigstore
