#pragma once

#include <memory>
#include <string>
#include <openssl/evp.h>
#include <boost/asio.hpp>
#include <boost/outcome/std_result.hpp>
#include <spdlog/spdlog.h>
#include "utils/Logging.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::http
{
  class IHttpClient;
}

namespace unfold::sigstore
{

  class TransparencyLogVerifier
  {
  public:
    explicit TransparencyLogVerifier(std::shared_ptr<unfold::http::IHttpClient> http_client);
    ~TransparencyLogVerifier() = default;

    boost::asio::awaitable<bool> verify_transparency_log(std::string bundle_content, std::string public_key_content);
    void set_rekor_public_key(const std::string &public_key_content);

  private:
    std::shared_ptr<unfold::http::IHttpClient> http_client_;
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:transparency")};
    EVP_PKEY *rekor_public_key_;

    boost::asio::awaitable<outcome::std_result<std::string>> download_transparency_log_entry(std::string entry_id);
    bool parse_rekor_response(const std::string &response, std::string &log_entry);
    bool verify_rekor_log_entry_signature(const std::string &log_entry, const std::string &signature_b64);
  };

} // namespace unfold::sigstore
