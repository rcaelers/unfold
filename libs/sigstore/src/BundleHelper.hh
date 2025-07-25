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

#ifndef BUNDLE_HELPER_HH
#define BUNDLE_HELPER_HH

#include <memory>
#include <optional>

#include <boost/outcome/std_result.hpp>
#include <boost/json.hpp>
#include <spdlog/spdlog.h>

#include "Certificate.hh"
#include "utils/Logging.hh"

#include <sigstore_bundle.pb.h>

namespace dev::sigstore::bundle::v1
{
  class Bundle;
}

namespace unfold::sigstore
{
  class BundleHelper
  {
  public:
    explicit BundleHelper(const dev::sigstore::bundle::v1::Bundle &bundle);
    ~BundleHelper() = default;

    BundleHelper(const BundleHelper &) = delete;
    BundleHelper &operator=(const BundleHelper &) = delete;
    BundleHelper(BundleHelper &&) noexcept = delete;
    BundleHelper &operator=(BundleHelper &&) noexcept = delete;

    std::string get_signature() const;
    std::shared_ptr<Certificate> get_certificate() const;
    std::optional<std::string> get_message_digest() const;
    std::optional<std::string> get_algorithm() const;
    int64_t get_log_index() const;

    const ::google::protobuf::RepeatedPtrField<::dev::sigstore::rekor::v1::TransparencyLogEntry> &get_transparency_log_entries() const;

    // std::string get_media_type() const;
    // bool has_transparency_log_entries() const;
    // size_t get_transparency_log_entry_count() const;
    // std::optional<int64_t> get_transparency_log_entry_index(size_t index) const;
    // std::vector<int64_t> get_all_transparency_log_indices() const;
    // bool is_valid() const;

  private:
    const dev::sigstore::bundle::v1::Bundle &bundle_;
    std::shared_ptr<Certificate> certificate_;

    std::shared_ptr<Certificate> extract_certificate() const;
    std::string extract_signature() const;
    std::optional<std::string> extract_message_digest() const;
    std::optional<std::string> extract_algorithm() const;
    int64_t extract_log_index() const;

  private:
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:bundle_loader")};
  };

} // namespace unfold::sigstore

#endif // BUNDLE_HELPER_HH
