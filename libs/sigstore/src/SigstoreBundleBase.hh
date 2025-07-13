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

#ifndef SIGSTORE_BUNDLE_BASE_HH
#define SIGSTORE_BUNDLE_BASE_HH

#include <string>
#include <memory>
#include <boost/outcome/std_result.hpp>
#include <boost/json.hpp>

#include "Certificate.hh"
#include "JsonUtils.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  class SigstoreBundleBase
  {
  public:
    virtual ~SigstoreBundleBase() = default;

    virtual std::string get_signature() const = 0;
    virtual const Certificate &get_certificate() const = 0;
    virtual int64_t get_log_index() const = 0;

    static outcome::std_result<std::unique_ptr<SigstoreBundleBase>> from_json(const std::string &json_str);

  private:
    JsonUtils json_utils_;

  protected:
    SigstoreBundleBase() = default;
  };
} // namespace unfold::sigstore

#endif // SIGSTORE_BUNDLE_BASE_HH
