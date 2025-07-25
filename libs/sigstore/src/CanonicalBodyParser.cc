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

#include "CanonicalBodyParser.hh"

#include <boost/json.hpp>
#include <memory>

#include "utils/Base64.hh"
#include "sigstore/SigstoreErrors.hh"

namespace unfold::sigstore
{
  outcome::std_result<LogEntry> CanonicalBodyParser::parse_from_base64_json(const std::string &base64_encoded_body)
  {
    try
      {
        std::string json_body = unfold::utils::Base64::decode(base64_encoded_body);
        return parse_from_json(json_body);
      }
    catch (const std::exception &e)
      {
        logger_->error("Failed to decode base64 encoded body: {}", e.what());
        return SigstoreError::InvalidTransparencyLog;
      }
  }

  outcome::std_result<LogEntry> CanonicalBodyParser::parse_from_json(const std::string &json_body)
  {
    try
      {
        boost::json::value json_val = boost::json::parse(json_body);
        if (!json_val.is_object())
          {
            logger_->error("Canonicalized body is not a valid JSON object");
            return SigstoreError::InvalidTransparencyLog;
          }

        const auto &obj = json_val.as_object();

        if (!obj.contains("kind") || !obj.at("kind").is_string())
          {
            logger_->error("Canonicalized body missing required 'kind' field");
            return SigstoreError::InvalidTransparencyLog;
          }

        if (!obj.contains("apiVersion") || !obj.at("apiVersion").is_string())
          {
            logger_->error("Canonicalized body missing required 'apiVersion' field");
            return SigstoreError::InvalidTransparencyLog;
          }

        auto api_version = std::string(obj.at("apiVersion").as_string());

        if (!obj.contains("spec") || !obj.at("spec").is_object())
          {
            logger_->error("Canonicalized body missing required 'spec' field");
            return SigstoreError::InvalidTransparencyLog;
          }

        const auto &spec_obj = obj.at("spec").as_object();
        const auto &kind = std::string(obj.at("kind").as_string());
        const auto &version = std::string(obj.at("apiVersion").as_string());

        if (kind == "hashedrekord" && version == "0.0.1")
          {
            auto parse_result = parse_hashed_rekord_spec(spec_obj);
            if (!parse_result)
              {
                return parse_result.error();
              }

            auto spec = std::move(parse_result.value());
            LogEntry entry{.kind = kind, .api_version = api_version, .spec = std::move(spec)};
            return std::move(entry);
          }
        logger_->error("Unsupported entry kind {} in canonicalized body", kind);
        return SigstoreError::InvalidTransparencyLog;
      }
    catch (const std::exception &e)
      {
        logger_->error("Exception while parsing canonicalized body JSON: {}", e.what());
        return SigstoreError::InvalidTransparencyLog;
      }
  }

  outcome::std_result<HashedRekord> CanonicalBodyParser::parse_hashed_rekord_spec(const boost::json::object &spec_obj)
  {
    try
      {
        if (!spec_obj.contains("data") || !spec_obj.at("data").is_object())
          {
            logger_->error("HashedRekord spec missing 'data' field");
            return SigstoreError::InvalidTransparencyLog;
          }

        const auto &data_obj = spec_obj.at("data").as_object();
        if (!data_obj.contains("hash") || !data_obj.at("hash").is_object())
          {
            logger_->error("HashedRekord spec data missing 'hash' field");
            return SigstoreError::InvalidTransparencyLog;
          }

        const auto &hash_obj = data_obj.at("hash").as_object();

        if (!hash_obj.contains("algorithm") || !hash_obj.at("algorithm").is_string())
          {
            logger_->error("HashedRekord spec hash missing 'algorithm' field");
            return SigstoreError::InvalidTransparencyLog;
          }
        if (!hash_obj.contains("value") || !hash_obj.at("value").is_string())
          {
            logger_->error("HashedRekord spec hash missing 'value' field");
            return SigstoreError::InvalidTransparencyLog;
          }

        if (!spec_obj.contains("signature") || !spec_obj.at("signature").is_object())
          {
            logger_->error("HashedRekord spec missing 'signature' field");
            return SigstoreError::InvalidTransparencyLog;
          }

        const auto &sig_obj = spec_obj.at("signature").as_object();

        if (!sig_obj.contains("content") || !sig_obj.at("content").is_string())
          {
            logger_->error("HashedRekord spec signature missing 'content' field");
            return SigstoreError::InvalidTransparencyLog;
          }
        if (!sig_obj.contains("publicKey") || !sig_obj.at("publicKey").is_object())
          {
            logger_->error("HashedRekord spec signature missing 'publicKey' field");
            return SigstoreError::InvalidTransparencyLog;
          }

        std::string signature_content = unfold::utils::Base64::decode(sig_obj.at("content").as_string().c_str());
        const auto &pubkey_obj = sig_obj.at("publicKey").as_object();

        if (!pubkey_obj.contains("content") || !pubkey_obj.at("content").is_string())
          {
            logger_->error("HashedRekord spec signature publicKey missing 'content' field");
            return SigstoreError::InvalidTransparencyLog;
          }

        auto pub_key_content = pubkey_obj.at("content").as_string();
        std::string cert_pem = unfold::utils::Base64::decode(std::string(pub_key_content));

        HashedRekord hashed_rekord{.hash_algorithm = std::string(hash_obj.at("algorithm").as_string()),
                                   .hash_value = std::string(hash_obj.at("value").as_string()),
                                   .signature = signature_content,
                                   .public_key = cert_pem};

        return hashed_rekord;
      }
    catch (const std::exception &e)
      {
        logger_->error("Exception while parsing HashedRekord spec: {}", e.what());
        return SigstoreError::InvalidTransparencyLog;
      }
  }

} // namespace unfold::sigstore
