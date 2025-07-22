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

#include "SigstoreBundleBase.hh"

#include "SigstoreLegacyBundle.hh"
#include "SigstoreStandardBundle.hh"
#include "sigstore/SigstoreErrors.hh"
#include <boost/json.hpp>
#include <memory>

namespace unfold::sigstore
{
  outcome::std_result<std::shared_ptr<SigstoreBundleBase>> SigstoreBundleBase::from_json(const std::string &json_str)
  {
    try
      {
        boost::json::value json_val = boost::json::parse(json_str);

        if (json_val.is_null())
          {
            return SigstoreError::JsonParseError;
          }

        // Check for standard bundle format (v0.3+) with mediaType and verificationMaterial
        if (json_val.is_object() && json_val.as_object().contains("mediaType")
            && json_val.as_object().contains("verificationMaterial"))
          {
            spdlog::debug("Detected Sigstore StandardBundle format");
            auto result = SigstoreStandardBundle::from_json(json_val);
            if (result)
              {
                return result.value();
              }
            return outcome::failure(result.error());
          }

        // Check for legacy bundle format with base64Signature
        if (json_val.is_object() && json_val.as_object().contains("base64Signature"))
          {
            spdlog::debug("Detected Sigstore LegacyBundle format");
            auto result = SigstoreLegacyBundle::from_json(json_val);
            if (result)
              {
                return result.value();
              }
            return outcome::failure(result.error());
          }

        // Unknown format
        return outcome::failure(make_error_code(SigstoreError::InvalidBundle));
      }
    catch (const std::exception &)
      {
        return outcome::failure(make_error_code(SigstoreError::JsonParseError));
      }
  }
} // namespace unfold::sigstore
