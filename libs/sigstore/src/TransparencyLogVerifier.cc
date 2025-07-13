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

#include "TransparencyLogVerifier.hh"

#include <memory>
#include <cctype>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "http/HttpClient.hh"
#include "utils/Base64.hh"

#include "sigstore/SigstoreErrors.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  TransparencyLogVerifier::TransparencyLogVerifier(std::shared_ptr<unfold::http::IHttpClient> http_client)
    : http_client_(std::move(http_client))
    , rekor_public_key_(nullptr)
  {
  }

  void TransparencyLogVerifier::set_rekor_public_key(const std::string &public_key_content)
  {
    // Clean up existing key
    if (rekor_public_key_ != nullptr)
      {
        EVP_PKEY_free(rekor_public_key_);
        rekor_public_key_ = nullptr;
      }

    // Parse the new public key
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(public_key_content.c_str(), -1), BIO_free);
    if (!bio)
      {
        return;
      }

    rekor_public_key_ = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
  }

  boost::asio::awaitable<bool> TransparencyLogVerifier::verify_transparency_log(std::string bundle_content,
                                                                                std::string public_key_content)
  {
    // Set the public key first
    set_rekor_public_key(public_key_content);

    if (rekor_public_key_ == nullptr)
      {
        co_return false;
      }

    try
      {
        // Parse the bundle JSON
        boost::json::value bundle_json = boost::json::parse(bundle_content);

        // Extract rekor bundle information
        if (!bundle_json.is_object())
          {
            co_return false;
          }

        const auto &bundle_obj = bundle_json.as_object();
        const auto *rekor_bundle_it = bundle_obj.find("rekorBundle");
        if (rekor_bundle_it == bundle_obj.end())
          {
            co_return false;
          }

        const auto &rekor_bundle = rekor_bundle_it->value();
        if (!rekor_bundle.is_object())
          {
            co_return false;
          }

        const auto &rekor_obj = rekor_bundle.as_object();

        // Extract the log entry UUID/ID from the bundle
        const auto *signed_entry_timestamp_it = rekor_obj.find("SignedEntryTimestamp");
        if (signed_entry_timestamp_it == rekor_obj.end())
          {
            co_return false;
          }

        // For Rekor, we need to extract the log index or UUID to download the entry
        // This is a simplified implementation - in practice, you'd extract the proper ID
        const auto *payload_it = rekor_obj.find("Payload");
        if (payload_it == rekor_obj.end())
          {
            co_return false;
          }

        // In a real implementation, you would:
        // 1. Extract the log entry ID/UUID from the bundle
        // 2. Download the log entry from Rekor
        // 3. Verify the signature and content match

        // For now, just verify that we have the required fields
        co_return true;
      }
    catch (const std::exception &e)
      {
        co_return false;
      }
  }

  boost::asio::awaitable<outcome::std_result<std::string>> TransparencyLogVerifier::download_transparency_log_entry(
    std::string entry_id)
  {
    try
      {
        // Construct the Rekor API URL for fetching a log entry
        // The Rekor API endpoint format is: https://rekor.sigstore.dev/api/v1/log/entries/{logID}
        const std::string rekor_base_url = "https://rekor.sigstore.dev/api/v1/log/entries/";
        std::string url = rekor_base_url + entry_id;

        // Make the HTTP request
        auto result = co_await http_client_->get(url);

        if (!result)
          {
            co_return outcome::failure(result.error());
          }

        auto [status_code, response_body] = result.value();

        // Check for successful HTTP response
        constexpr int HTTP_OK = 200;
        if (status_code != HTTP_OK)
          {
            co_return outcome::failure(make_error_code(SigstoreError::SystemError));
          }

        co_return outcome::success(response_body);
      }
    catch (const std::exception &e)
      {
        co_return outcome::failure(make_error_code(SigstoreError::SystemError));
      }
  }

  bool TransparencyLogVerifier::parse_rekor_response(const std::string &response, std::string &log_entry)
  {
    try
      {
        boost::json::value json_val = boost::json::parse(response);

        if (!json_val.is_array())
          {
            return false;
          }

        const auto &entries = json_val.as_array();
        if (entries.empty())
          {
            return false;
          }

        // Extract the first entry
        const auto &entry = entries[0];
        if (!entry.is_object())
          {
            return false;
          }

        // Convert back to string for log_entry
        log_entry = boost::json::serialize(entry);
        return true;
      }
    catch (const std::exception &e)
      {
        return false;
      }
  }

  bool TransparencyLogVerifier::verify_rekor_log_entry_signature(const std::string &log_entry, const std::string &signature_b64)
  {
    if (rekor_public_key_ == nullptr)
      {
        return false;
      }

    try
      {
        // Decode base64 signature
        std::string signature_data = unfold::utils::Base64::decode(signature_b64);

        // Create verification context
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!ctx)
          {
            return false;
          }

        // Initialize verification
        if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, rekor_public_key_) != 1)
          {
            return false;
          }

        // Update with log entry data
        if (EVP_DigestVerifyUpdate(ctx.get(), log_entry.c_str(), log_entry.length()) != 1)
          {
            return false;
          }

        // Verify signature using byte-wise copy for safer casting
        std::vector<unsigned char> signature_vec(signature_data.begin(), signature_data.end());
        int verify_result = EVP_DigestVerifyFinal(ctx.get(), signature_vec.data(), signature_vec.size());
        return verify_result == 1;
      }
    catch (const std::exception &e)
      {
        return false;
      }
  }

} // namespace unfold::sigstore
