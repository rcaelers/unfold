// Copyright (C) 2022 Rob Caelers <rob.caelers@gmail.com>
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

#include "http/HttpClientErrors.hh"

using namespace unfold::http;

namespace
{
  struct HttpClientErrorCategory : std::error_category
  {
    const char *name() const noexcept override
    {
      return "httpclient";
    }
    std::string message(int ev) const override;
  };

  std::string HttpClientErrorCategory::message(int ev) const
  {
    switch (static_cast<HttpClientErrc>(ev))
      {
      case HttpClientErrc::Success:
        return "signature correct";
      case HttpClientErrc::MalformedURL:
        return "malformed URL";
      case HttpClientErrc::InternalError:
        return "internal error";
      case HttpClientErrc::NameResolutionFailed:
        return "name resolution failed";
      case HttpClientErrc::ConnectionRefused:
        return "connection refused";
      case HttpClientErrc::CommunicationError:
        return "connection error";
      case HttpClientErrc::InvalidCertificate:
        return "invalid certificate";
      }
    return "(unknown)";
  }

  const HttpClientErrorCategory globalHttpClientErrorCategory{};
} // namespace

std::error_code
unfold::http::make_error_code(HttpClientErrc ec)
{
  return std::error_code{static_cast<int>(ec), globalHttpClientErrorCategory};
}
