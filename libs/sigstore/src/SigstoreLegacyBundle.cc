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

#include "SigstoreLegacyBundle.hh"

#include "Certificate.hh"
#include "sigstore/SigstoreErrors.hh"
#include "utils/Base64.hh"

#include <boost/json.hpp>

namespace unfold::sigstore
{

  SigstoreLegacyBundle::SigstoreLegacyBundle(std::string signature, std::shared_ptr<Certificate> certificate, int64_t log_index)
    : signature_(std::move(signature))
    , certificate_(std::move(certificate))
    , log_index_(log_index)
  {
  }

  outcome::std_result<std::shared_ptr<SigstoreLegacyBundle>> SigstoreLegacyBundle::from_json(const boost::json::value &json_val)
  {
    SigstoreLegacyBundleLoader loader;
    return loader.from_json(json_val);
  }

  outcome::std_result<std::shared_ptr<SigstoreLegacyBundle>> SigstoreLegacyBundleLoader::from_json(
    const boost::json::value &json_val)
  {
    try
      {
        if (!json_val.is_object())
          {
            logger_->error("Invalid JSON for Sigstore LegacyBundle");
            return SigstoreError::InvalidBundle;
          }

        std::string signature = json_utils_.extract_string(json_val, "base64Signature");
        if (signature.empty())
          {
            logger_->error("Missing or empty base64Signature");
            return SigstoreError::InvalidBundle;
          }

        std::string certificate = json_utils_.extract_string(json_val, "cert");
        if (certificate.empty())
          {
            logger_->error("Missing or empty cert");
            return SigstoreError::InvalidBundle;
          }

        auto rekor_bundle = json_utils_.extract_object(json_val, "rekorBundle");
        if (rekor_bundle.is_null())
          {
            logger_->error("rekorBundle is missing");
            return SigstoreError::InvalidBundle;
          }
        auto payload = json_utils_.extract_object(rekor_bundle, "Payload");
        if (payload.is_null())
          {
            logger_->error("Payload is missing");
            return SigstoreError::InvalidBundle;
          }

        int64_t log_index = payload.at("logIndex").as_int64();

        auto cert = Certificate::from_pem(unfold::utils::Base64::decode(certificate));
        if (cert.has_error())
          {
            logger_->error("Invalid certificate in Sigstore LegacyBundle: {}", cert.error().message());
            return cert.error();
          }
        return std::make_shared<SigstoreLegacyBundle>(std::move(signature),
                                                      std::make_shared<Certificate>(std::move(cert.value())),
                                                      log_index);
      }
    catch (const std::exception &)
      {
        return SigstoreError::JsonParseError;
      }
  }

} // namespace unfold::sigstore
