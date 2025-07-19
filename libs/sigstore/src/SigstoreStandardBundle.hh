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

#ifndef SIGSTORE_STANDARD_BUNDLE_HH
#define SIGSTORE_STANDARD_BUNDLE_HH

#include <optional>
#include "SigstoreBundleBase.hh"
#include "TransparencyLogEntry.hh"

#include <vector>

#include <boost/json.hpp>

namespace unfold::sigstore
{

  struct MessageSignature
  {
    std::string algorithm; // from messageDigest.algorithm
    std::string digest;    // from messageDigest.digest
    std::string signature; // signature field
  };

  class SigstoreStandardBundle : public SigstoreBundleBase
  {
  public:
    SigstoreStandardBundle(Certificate certificate, MessageSignature message_sig, std::vector<TransparencyLogEntry> tlog_entries);

    static outcome::std_result<std::shared_ptr<SigstoreStandardBundle>> from_json(const boost::json::value &json_val);

    std::string get_signature() const override
    {
      return message_signature_.signature;
    }
    const Certificate &get_certificate() const override
    {
      return certificate_;
    }
    std::optional<std::string> get_message_digest() const override
    {
      return message_signature_.digest;
    }
    std::optional<std::string> get_algorithm() const override
    {
      return message_signature_.algorithm;
    }
    int64_t get_log_index() const override;

    const std::vector<TransparencyLogEntry> &get_transparency_log_entries() const
    {
      return tlog_entries_;
    }

  private:
    Certificate certificate_;
    MessageSignature message_signature_;
    std::vector<TransparencyLogEntry> tlog_entries_;
  };

  class SigstoreStandardBundleLoader
  {
  public:
    SigstoreStandardBundleLoader() = default;

    outcome::std_result<std::shared_ptr<SigstoreStandardBundle>> from_json(const boost::json::value &json_val);

  private:
    std::string extract_certificate_from_verification_material(const boost::json::value &verification_material);
    outcome::std_result<MessageSignature> parse_message_signature(const boost::json::value &json_val);

  private:
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:standard_bundle")};
    JsonUtils json_utils_;

    std::string media_type_;
    MessageSignature message_signature_;
    std::vector<TransparencyLogEntry> tlog_entries_;
  };

} // namespace unfold::sigstore

#endif // SIGSTORE_STANDARD_BUNDLE_HH
