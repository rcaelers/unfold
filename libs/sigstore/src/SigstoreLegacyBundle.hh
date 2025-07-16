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

#ifndef SIGSTORE_LEGACY_BUNDLE_HH
#define SIGSTORE_LEGACY_BUNDLE_HH

#include "Certificate.hh"
#include "SigstoreBundleBase.hh"

#include <boost/json.hpp>

namespace unfold::sigstore
{
  class SigstoreLegacyBundle : public SigstoreBundleBase
  {
  public:
    SigstoreLegacyBundle(std::string signature, Certificate certificate, int64_t log_index);

    static outcome::std_result<std::shared_ptr<SigstoreLegacyBundle>> from_json(const boost::json::value &json_val);

    std::string get_signature() const override
    {
      return signature_;
    }
    const Certificate &get_certificate() const override
    {
      return certificate_;
    }
    int64_t get_log_index() const override
    {
      return log_index_;
    }

  private:
    std::string signature_;
    Certificate certificate_;
    int64_t log_index_;
  };

  class SigstoreLegacyBundleLoader
  {
  public:
    SigstoreLegacyBundleLoader() = default;

    outcome::std_result<std::shared_ptr<SigstoreLegacyBundle>> from_json(const boost::json::value &json_val);

  private:
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:legacy_bundle")};
    JsonUtils json_utils_;
  };

} // namespace unfold::sigstore

#endif // SIGSTORE_LEGACY_BUNDLE_HH
