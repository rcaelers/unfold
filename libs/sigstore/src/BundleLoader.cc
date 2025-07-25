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

#include "BundleLoader.hh"

#include <fstream>
#include <google/protobuf/util/json_util.h>

#include "sigstore/SigstoreErrors.hh"
#include "Certificate.hh"

namespace unfold::sigstore
{

  outcome::std_result<dev::sigstore::bundle::v1::Bundle> SigstoreBundleLoader::load_from_file(const std::filesystem::path &file_path)
  {
    if (!std::filesystem::exists(file_path))
      {
        logger_->error("File does not exist: {}", file_path.string());
        return SigstoreError::InvalidBundle;
      }

    try
      {
        std::ifstream file(file_path, std::ios::in | std::ios::binary);
        if (!file.is_open())
          {
            logger_->error("Failed to open file: {}", file_path.string());
            return SigstoreError::InvalidBundle;
          }

        std::string json_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        return load_from_json(json_content);
      }
    catch (const std::exception &e)
      {
        logger_->error("Exception while reading file {}: {}", file_path.string(), e.what());
        return SigstoreError::InvalidBundle;
      }
  }

  outcome::std_result<dev::sigstore::bundle::v1::Bundle> SigstoreBundleLoader::load_from_json(const std::string &json_content)
  {
    dev::sigstore::bundle::v1::Bundle bundle;

    google::protobuf::util::JsonParseOptions options;
    options.ignore_unknown_fields = false;
    options.case_insensitive_enum_parsing = true;

    auto status = google::protobuf::util::JsonStringToMessage(json_content, &bundle, options);

    if (!status.ok())
      {
        logger_->error("Failed to parse JSON Bundle: {}", std::string(status.message()));
        return SigstoreError::InvalidBundle;
      }
    auto validation_result = validate(bundle);
    if (!validation_result)
      {
        logger_->error("Bundle validation failed: {}", validation_result.error().message());
        return validation_result.error();
      }

    return bundle;
  }

  outcome::std_result<dev::sigstore::bundle::v1::Bundle> SigstoreBundleLoader::validate(const dev::sigstore::bundle::v1::Bundle &bundle) const
  {
    if (bundle.media_type() != "application/vnd.dev.sigstore.bundle.v0.3+json")
      {
        logger_->error("Bundle has invalid media type: {}", bundle.media_type());
        return SigstoreError::InvalidBundle;
      }
    if (!bundle.has_verification_material())
      {
        logger_->error("Bundle does not contain verification material");
        return SigstoreError::InvalidBundle;
      }
    if (!bundle.verification_material().has_certificate())
      {
        logger_->error("Bundle verification material does not contain a certificate");
        return SigstoreError::InvalidBundle;
      }
    if (bundle.verification_material().certificate().raw_bytes().empty())
      {
        logger_->error("Bundle verification material certificate does not contain raw bytes");
        return SigstoreError::InvalidBundle;
      }
    const auto &cert = Certificate::from_cert(bundle.verification_material().certificate());
    if (!cert.has_value())
      {
        logger_->error("Bundle verification material certificate is not valid");
        return SigstoreError::InvalidBundle;
      }
    if (bundle.verification_material().tlog_entries().empty())
      {
        logger_->error("Bundle verification material does not contain any transparency log entries");
        return SigstoreError::InvalidBundle;
      }
    if (!bundle.has_message_signature())
      {
        logger_->error("Bundle does not contain a message signature");
        return SigstoreError::InvalidBundle;
      }
    if (bundle.message_signature().signature().empty())
      {
        logger_->error("Bundle message signature does not contain content");
        return SigstoreError::InvalidBundle;
      }
    return outcome::success(bundle);
  }

} // namespace unfold::sigstore
