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

#ifndef XMLDSIG_VERIFIER_HH
#define XMLDSIG_VERIFIER_HH

#include <string>
#include <memory>
#include <vector>
#include <system_error>

#include <boost/outcome/std_result.hpp>

#include "utils/Logging.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::crypto
{

  struct XMLDSigInfo
  {
    std::string signature_id;
    std::string signature_method;
    std::string canonicalization_method;
    std::string digest_method;
    std::vector<std::string> signed_element_ids;
    std::string key_info;
    bool has_x509_certificate = false;
    std::string x509_certificate;
  };

  enum class XMLDSigError : int
  {
    InvalidXML = 1,
    NoSignature,
    InvalidSignature,
    InvalidCertificate,
    InvalidKeyInfo,
    VerificationFailed,
    LibraryError,
    InitializationFailed
  };

  class XMLDSigErrorCategory : public std::error_category
  {
  public:
    const char *name() const noexcept override
    {
      return "xmldsig";
    }

    std::string message(int ev) const override
    {
      switch (static_cast<XMLDSigError>(ev))
        {
        case XMLDSigError::InvalidXML:
          return "Invalid XML";
        case XMLDSigError::NoSignature:
          return "No signature found";
        case XMLDSigError::InvalidSignature:
          return "Invalid signature";
        case XMLDSigError::InvalidCertificate:
          return "Invalid certificate";
        case XMLDSigError::InvalidKeyInfo:
          return "Invalid key info";
        case XMLDSigError::VerificationFailed:
          return "Verification failed";
        case XMLDSigError::LibraryError:
          return "Library error";
        case XMLDSigError::InitializationFailed:
          return "Initialization failed";
        default:
          return "Unknown error";
        }
    }
  };

  const std::error_category &xmldsig_error_category();
  std::error_code make_error_code(XMLDSigError e);

  class XMLDSigVerifier
  {
  public:
    static outcome::std_result<XMLDSigVerifier> create();

    ~XMLDSigVerifier();

    XMLDSigVerifier(const XMLDSigVerifier &) = delete;
    XMLDSigVerifier &operator=(const XMLDSigVerifier &) = delete;
    XMLDSigVerifier(XMLDSigVerifier &&) noexcept;
    XMLDSigVerifier &operator=(XMLDSigVerifier &&) noexcept;

    outcome::std_result<void> add_trusted_public_key(const std::string &key_name, const std::string &public_key_pem);
    outcome::std_result<void> clear_trusted_keys();

    outcome::std_result<XMLDSigInfo> verify(const std::string &xml_content);
    outcome::std_result<XMLDSigInfo> get_signature_info(const std::string &xml_content);

    static bool has_signature(const std::string &xml_content);

  private:
    XMLDSigVerifier();

    class Impl;
    std::unique_ptr<Impl> pimpl;
    std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:xmldsig")};
  };

} // namespace unfold::crypto

namespace std
{
  template<>
  struct is_error_code_enum<unfold::crypto::XMLDSigError> : true_type
  {
  };
} // namespace std

#endif // XMLDSIG_VERIFIER_HH
