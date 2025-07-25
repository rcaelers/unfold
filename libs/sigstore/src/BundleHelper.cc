// Copyright (C) 202Caelers <rob.caelers@gmail.com>
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

#include "BundleHelper.hh"

#include <boost/json/serialize.hpp>
#include <sigstore_bundle.pb.h>

namespace unfold::sigstore
{
  BundleHelper::BundleHelper(const dev::sigstore::bundle::v1::Bundle &bundle)
    : bundle_(bundle)
    , certificate_(extract_certificate())
  {
  }

  std::string BundleHelper::get_signature() const
  {
    return extract_signature();
  }

  std::shared_ptr<Certificate> BundleHelper::get_certificate() const
  {
    return certificate_;
  }

  std::optional<std::string> BundleHelper::get_message_digest() const
  {
    return extract_message_digest();
  }

  std::optional<std::string> BundleHelper::get_algorithm() const
  {
    return extract_algorithm();
  }

  int64_t BundleHelper::get_log_index() const
  {
    return extract_log_index();
  }

  const ::google::protobuf::RepeatedPtrField<::dev::sigstore::rekor::v1::TransparencyLogEntry> &BundleHelper::get_transparency_log_entries() const
  {
    return bundle_.verification_material().tlog_entries();
  }

  // std::string BundleHelper::get_media_type() const
  // {
  //   if (!bundle_)
  //     {
  //       return "";
  //     }
  //   return bundle_->media_type();
  // }

  // bool BundleHelper::has_transparency_log_entries() const
  // {
  //   if (!bundle_ || !bundle_->has_verification_material())
  //     {
  //       return false;
  //     }

  //   const auto &verification_material = bundle_->verification_material();
  //   return verification_material.tlog_entries_size() > 0;
  // }

  // size_t BundleHelper::get_transparency_log_entry_count() const
  // {
  //   if (!bundle_ || !bundle_->has_verification_material())
  //     {
  //       return 0;
  //     }

  //   const auto &verification_material = bundle_->verification_material();
  //   return static_cast<size_t>(verification_material.tlog_entries_size());
  // }

  // std::optional<int64_t> BundleHelper::get_transparency_log_entry_index(size_t index) const
  // {
  //   if (!bundle_ || !bundle_->has_verification_material())
  //     {
  //       return std::nullopt;
  //     }

  //   const auto &verification_material = bundle_->verification_material();
  //   if (static_cast<int>(index) >= verification_material.tlog_entries_size())
  //     {
  //       return std::nullopt;
  //     }

  //   const auto &entry = verification_material.tlog_entries(static_cast<int>(index));
  //   if (entry.has_log_index())
  //     {
  //       return entry.log_index();
  //     }

  //   return std::nullopt;
  // }

  // std::vector<int64_t> BundleHelper::get_all_transparency_log_indices() const
  // {
  //   std::vector<int64_t> indices;

  //   if (!bundle_ || !bundle_->has_verification_material())
  //     {
  //       return indices;
  //     }

  //   const auto &verification_material = bundle_->verification_material();
  //   for (int i = 0; i < verification_material.tlog_entries_size(); ++i)
  //     {
  //       const auto &entry = verification_material.tlog_entries(i);
  //       if (entry.has_log_index())
  //         {
  //           indices.push_back(entry.log_index());
  //         }
  //     }

  //   return indices;
  // }

  // bool BundleHelper::is_valid() const
  // {
  //   if (!bundle_)
  //     {
  //       return false;
  //     }

  //   // Check for required fields
  //   if (bundle_->media_type().empty())
  //     {
  //       return false;
  //     }

  //   if (!bundle_->has_verification_material())
  //     {
  //       return false;
  //     }

  //   const auto &verification_material = bundle_->verification_material();

  //   // Should have at least one certificate
  //   if (verification_material.x509_certificate_chain().certificates_size() == 0)
  //     {
  //       return false;
  //     }

  //   // Should have at least one transparency log entry
  //   if (verification_material.tlog_entries_size() == 0)
  //     {
  //       return false;
  //     }

  //   // Should have message signature
  //   if (!bundle_->has_message_signature())
  //     {
  //       return false;
  //     }

  //   return true;
  // }

  std::shared_ptr<Certificate> BundleHelper::extract_certificate() const
  {
    if (!bundle_.has_verification_material())
      {
        logger_->warn("Bundle has no verification material");
        return nullptr;
      }

    const auto &verification_material = bundle_.verification_material();
    if (!verification_material.has_certificate())
      {
        logger_->warn("Bundle has no certificate");
        return nullptr;
      }

    try
      {
        const auto &cert_data = verification_material.certificate().raw_bytes();
        auto certificate = Certificate::from_der(cert_data);
        if (!certificate)
          {
            logger_->error("Failed to parse certificate from bundle: {}", certificate.error().message());
            return nullptr;
          }

        return std::make_shared<Certificate>(std::move(certificate.value()));
      }
    catch (const std::exception &e)
      {
        logger_->error("Exception while extracting certificate: {}", e.what());
        return nullptr;
      }
  }

  std::string BundleHelper::extract_signature() const
  {
    if (!bundle_.has_message_signature())
      {
        return "";
      }

    const auto &message_signature = bundle_.message_signature();
    return message_signature.signature();
  }

  std::optional<std::string> BundleHelper::extract_message_digest() const
  {
    if (!bundle_.has_message_signature())
      {
        return std::nullopt;
      }

    const auto &message_signature = bundle_.message_signature();
    if (!message_signature.has_message_digest())
      {
        return std::nullopt;
      }

    const auto &message_digest = message_signature.message_digest();
    return message_digest.digest();
  }

  std::optional<std::string> BundleHelper::extract_algorithm() const
  {
    if (!bundle_.has_message_signature())
      {
        return std::nullopt;
      }

    const auto &message_signature = bundle_.message_signature();
    if (!message_signature.has_message_digest())
      {
        return std::nullopt;
      }

    const auto &message_digest = message_signature.message_digest();

    // Convert the enum to string
    switch (message_digest.algorithm())
      {
      case dev::sigstore::common::v1::HashAlgorithm::SHA2_256:
        return "sha256";
      case dev::sigstore::common::v1::HashAlgorithm::SHA2_384:
        return "sha384";
      case dev::sigstore::common::v1::HashAlgorithm::SHA2_512:
        return "sha512";
      case dev::sigstore::common::v1::HashAlgorithm::SHA3_256:
        return "sha3-256";
      case dev::sigstore::common::v1::HashAlgorithm::SHA3_384:
        return "sha3-384";
      default:
        logger_->warn("Unknown hash algorithm: {}", static_cast<int>(message_digest.algorithm()));
        return std::nullopt;
      }
  }

  int64_t BundleHelper::extract_log_index() const
  {
    if (!bundle_.has_verification_material())
      {
        return -1;
      }

    const auto &verification_material = bundle_.verification_material();
    if (verification_material.tlog_entries_size() == 0)
      {
        return -1;
      }

    const auto &entry = verification_material.tlog_entries(0);
    return entry.log_index();
  }

} // namespace unfold::sigstore
