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

#include "SigstoreStandardBundle.hh"

#include "Certificate.hh"
#include "TransparencyLogEntry.hh"
#include "sigstore/SigstoreErrors.hh"
#include "utils/Base64.hh"

#include <boost/json.hpp>
#include <string>
#include <cstdlib>

namespace unfold::sigstore
{
  outcome::std_result<std::shared_ptr<SigstoreStandardBundle>> SigstoreStandardBundle::from_json(
    const boost::json::value &json_val)
  {
    SigstoreStandardBundleLoader loader;
    return loader.from_json(json_val);
  }

  SigstoreStandardBundle::SigstoreStandardBundle(std::shared_ptr<Certificate> certificate,
                                                 MessageSignature message_sig,
                                                 std::vector<TransparencyLogEntry> tlog_entries)
    : certificate_(std::move(certificate))
    , message_signature_(std::move(message_sig))
    , tlog_entries_(std::move(tlog_entries))
  {
  }

  int64_t SigstoreStandardBundle::get_log_index() const
  {
    if (!tlog_entries_.empty())
      {
        return tlog_entries_[0].log_index;
      }
    return 0;
  }

  outcome::std_result<std::shared_ptr<SigstoreStandardBundle>> SigstoreStandardBundleLoader::from_json(
    const boost::json::value &json_val)
  {
    try
      {
        if (!json_val.is_object())
          {
            logger_->error("Invalid JSON for Sigstore StandardBundle");
            return SigstoreError::InvalidBundle;
          }

        const auto &obj = json_val.as_object();

        std::string media_type;
        if (const auto *it = obj.if_contains("mediaType"); it != nullptr && it->is_string())
          {
            media_type = std::string(it->as_string());
          }

        if (media_type.empty())
          {
            logger_->error("Missing mediaType in Sigstore StandardBundle");
            return SigstoreError::InvalidBundle;
          }

        boost::json::value verification_material;
        if (const auto *it = obj.if_contains("verificationMaterial"); it != nullptr)
          {
            verification_material = *it;
          }

        if (verification_material.is_null())
          {
            logger_->error("Missing verificationMaterial in Sigstore StandardBundle");
            return SigstoreError::InvalidBundle;
          }

        std::string certificate = extract_certificate_from_verification_material(verification_material);
        if (certificate.empty())
          {
            logger_->error("Missing certificate in Sigstore StandardBundle");
            return SigstoreError::InvalidBundle;
          }

        auto message_sig_result = parse_message_signature(json_val);
        if (!message_sig_result)
          {
            logger_->error("Failed to parse message signature: {}", message_sig_result.error().message());
            return message_sig_result.error();
          }

        auto cert = Certificate::from_der(unfold::utils::Base64::decode(certificate));
        if (cert.has_error())
          {
            logger_->error("Invalid certificate in Sigstore StandardBundle: {} {}", cert.error().message(), certificate);
            return cert.error();
          }

        std::vector<TransparencyLogEntry> tlog_entries_;
        if (verification_material.is_object() && verification_material.as_object().contains("tlogEntries"))
          {
            const auto &tlog_entries_json = verification_material.as_object().at("tlogEntries");
            if (tlog_entries_json.is_array())
              {
                TransparencyLogEntryParser parser;
                for (const auto &entry_json: tlog_entries_json.as_array())
                  {
                    auto entry_result = parser.parse(entry_json);
                    if (entry_result)
                      {
                        tlog_entries_.push_back(entry_result.value());
                      }
                  }
              }
          }

        return std::make_shared<SigstoreStandardBundle>(std::make_shared<Certificate>(std::move(cert.value())),
                                                        message_sig_result.value(),
                                                        std::move(tlog_entries_));
      }
    catch (const std::exception &e)
      {
        logger_->error("Failed to parse Sigstore StandardBundle JSON: {}", e.what());
        return SigstoreError::JsonParseError;
      }
  }
  outcome::std_result<MessageSignature> SigstoreStandardBundleLoader::parse_message_signature(const boost::json::value &json_val)
  {
    if (!json_val.is_object())
      {
        logger_->error("Missing messageSignature in Sigstore StandardBundle");
        return outcome::failure(make_error_code(SigstoreError::InvalidBundle));
      }

    const auto &obj = json_val.as_object();
    boost::json::value message_sig_obj;
    if (const auto *it = obj.if_contains("messageSignature"); it != nullptr)
      {
        message_sig_obj = *it;
      }

    if (message_sig_obj.is_null())
      {
        logger_->error("Missing messageSignature in Sigstore StandardBundle");
        return outcome::failure(make_error_code(SigstoreError::InvalidBundle));
      }

    if (!message_sig_obj.is_object())
      {
        logger_->error("Invalid messageSignature in Sigstore StandardBundle");
        return outcome::failure(make_error_code(SigstoreError::InvalidBundle));
      }

    const auto &msg_sig_obj = message_sig_obj.as_object();
    MessageSignature message_sig;

    if (const auto *it = msg_sig_obj.if_contains("signature"); it != nullptr && it->is_string())
      {
        message_sig.signature = std::string(it->as_string());
      }

    if (message_sig.signature.empty())
      {
        logger_->error("Missing signature in messageSignature of Sigstore StandardBundle");
        return outcome::failure(make_error_code(SigstoreError::InvalidBundle));
      }

    if (const auto *it = msg_sig_obj.if_contains("messageDigest"); it != nullptr && it->is_object())
      {
        const auto &digest_obj = it->as_object();
        if (const auto *alg_it = digest_obj.if_contains("algorithm"); alg_it != nullptr && alg_it->is_string())
          {
            message_sig.algorithm = std::string(alg_it->as_string());
          }
        if (const auto *dig_it = digest_obj.if_contains("digest"); dig_it != nullptr && dig_it->is_string())
          {
            message_sig.digest = std::string(dig_it->as_string());
          }
      }

    return message_sig;
  }

  std::string SigstoreStandardBundleLoader::extract_certificate_from_verification_material(
    const boost::json::value &verification_material)
  {
    if (!verification_material.is_object())
      {
        return "";
      }

    const auto &obj = verification_material.as_object();
    if (const auto *it = obj.if_contains("certificate"); it != nullptr && it->is_object())
      {
        const auto &cert_obj = it->as_object();
        if (const auto *raw_it = cert_obj.if_contains("rawBytes"); raw_it != nullptr && raw_it->is_string())
          {
            return std::string(raw_it->as_string());
          }
      }
    return "";
  }

} // namespace unfold::sigstore
