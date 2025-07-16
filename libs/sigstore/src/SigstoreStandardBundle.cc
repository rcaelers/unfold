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
#include "JsonUtils.hh"
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

  SigstoreStandardBundle::SigstoreStandardBundle(Certificate certificate,
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
        JsonUtils json_utils;

        if (!json_val.is_object())
          {
            logger_->error("Invalid JSON for Sigstore StandardBundle");
            return SigstoreError::InvalidBundle;
          }

        std::string media_type = json_utils.extract_string(json_val, "mediaType");
        if (media_type.empty())
          {
            logger_->error("Missing mediaType in Sigstore StandardBundle");
            return SigstoreError::InvalidBundle;
          }

        auto verification_material = json_utils.extract_object(json_val, "verificationMaterial");
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

        return std::make_shared<SigstoreStandardBundle>(std::move(cert.value()),
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
    JsonUtils json_utils;
    auto message_sig_obj = json_utils.extract_object(json_val, "messageSignature");
    if (message_sig_obj.is_null())
      {
        logger_->error("Missing messageSignature in Sigstore StandardBundle");
        return outcome::failure(make_error_code(SigstoreError::InvalidBundle));
      }

    MessageSignature message_sig;
    message_sig.signature = json_utils.extract_string(message_sig_obj, "signature");
    if (message_sig.signature.empty())
      {
        logger_->error("Missing signature in messageSignature of Sigstore StandardBundle");
        return outcome::failure(make_error_code(SigstoreError::InvalidBundle));
      }

    auto message_digest = json_utils.extract_object(message_sig_obj, "messageDigest");
    if (!message_digest.is_null())
      {
        message_sig.algorithm = json_utils.extract_string(message_digest, "algorithm");
        message_sig.digest = json_utils.extract_string(message_digest, "digest");
      }

    return message_sig;
  }

  std::string SigstoreStandardBundleLoader::extract_certificate_from_verification_material(
    const boost::json::value &verification_material)
  {
    JsonUtils json_utils;

    auto certificate_obj = json_utils.extract_object(verification_material, "certificate");
    if (!certificate_obj.is_null())
      {
        return json_utils.extract_string(certificate_obj, "rawBytes");
      }
    return "";
  }

} // namespace unfold::sigstore
