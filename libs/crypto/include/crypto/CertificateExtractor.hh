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

#ifndef CERTIFICATE_EXTRACTOR_HH
#define CERTIFICATE_EXTRACTOR_HH

#include <minwindef.h>
#include <string>
#include <vector>
#include <chrono>
#include <boost/outcome/std_result.hpp>

#include <windows.h>
#include <wincrypt.h>

namespace outcome = boost::outcome_v2;

namespace unfold::crypto
{

  struct CertificateInfo
  {
    bool is_signed{false};
    bool is_valid{false};
    std::string subject_name;
    std::string issuer_name;
    std::string thumbprint;
    std::string serial_number;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    std::vector<std::string> certificate_chain;
    std::string signature_algorithm;
    std::string hash_algorithm;
  };

  enum class CertificateError : int
  {
    FileNotFound,
    NotSigned,
    InvalidSignature,
    CertificateExpired,
    UntrustedRoot,
    SystemError
  };

  class CertificateErrorCategory : public std::error_category
  {
  public:
    const char *name() const noexcept override
    {
      return "certificate";
    }

    std::string message(int ev) const override
    {
      switch (static_cast<CertificateError>(ev))
        {
        case CertificateError::FileNotFound:
          return "File not found";
        case CertificateError::NotSigned:
          return "Not signed";
        case CertificateError::InvalidSignature:
          return "Invalid signature";
        case CertificateError::CertificateExpired:
          return "Certificate expired";
        case CertificateError::UntrustedRoot:
          return "Untrusted root";
        case CertificateError::SystemError:
          return "System error";
        default:
          return "Unknown error";
        }
    }
  };

  const std::error_category &certificate_error_category();
  std::error_code make_error_code(CertificateError e);

  class CertificateExtractor
  {
  public:
    static outcome::std_result<CertificateInfo> extract_windows_authenticode(const std::string &file_path);

  private:
    static std::string get_certificate_name(PCCERT_CONTEXT cert_context, DWORD name_type);
    static std::string get_certificate_thumbprint(PCCERT_CONTEXT cert_context);
    static std::chrono::system_clock::time_point filetime_to_time_point(const FILETIME &ft);
  };

} // namespace unfold::crypto

#endif // CERTIFICATE_EXTRACTOR_HH
