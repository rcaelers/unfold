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

#include "crypto/CertificateExtractor.hh"

#ifdef _WIN32
#  include <windows.h>
#  include <wintrust.h>
#  include <softpub.h>
#  include <wincrypt.h>
#  include <mscat.h>
#  include <ncrypt.h>
#  include <bcrypt.h>
#  include <imagehlp.h>
#  include <iostream>
#  include <iomanip>
#  include <sstream>
#endif

#include "utils/Logging.hh"

namespace unfold::crypto
{

  const std::error_category &certificate_error_category()
  {
    static CertificateErrorCategory category;
    return category;
  }

  std::error_code make_error_code(CertificateError e)
  {
    return {static_cast<int>(e), certificate_error_category()};
  }

  namespace
  {
    constexpr uint64_t FILETIME_TO_UNIX_EPOCH_DIFF = 11644473600ULL; // Seconds between 1601 and 1970
    constexpr uint64_t FILETIME_TICKS_PER_SECOND = 10000000ULL;      // 100-nanosecond intervals per second

    std::string get_certificate_name_helper(PCCERT_CONTEXT cert_context, DWORD name_type)
    {
      DWORD name_size = CertGetNameStringA(cert_context, name_type, 0, nullptr, nullptr, 0);
      if (name_size <= 1)
        {
          return "";
        }

      std::vector<char> name_buffer(name_size);
      CertGetNameStringA(cert_context, name_type, 0, nullptr, name_buffer.data(), name_size);

      // Convert to string (remove null terminator)
      return std::string(name_buffer.begin(), name_buffer.end() - 1);
    }

    std::string get_certificate_thumbprint_helper(PCCERT_CONTEXT cert_context)
    {
      DWORD thumbprint_size = 0;
      if (CertGetCertificateContextProperty(cert_context, CERT_SHA1_HASH_PROP_ID, nullptr, &thumbprint_size) == 0)
        {
          return "";
        }

      std::vector<BYTE> thumbprint_buffer(thumbprint_size);
      if (CertGetCertificateContextProperty(cert_context, CERT_SHA1_HASH_PROP_ID, thumbprint_buffer.data(), &thumbprint_size)
          == 0)
        {
          return "";
        }

      std::stringstream ss;
      for (DWORD i = 0; i < thumbprint_size; i++)
        {
          ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(thumbprint_buffer[i]);
        }

      return ss.str();
    }

    std::chrono::system_clock::time_point filetime_to_time_point_helper(const FILETIME &ft)
    {
      ULARGE_INTEGER uli;
      uli.LowPart = ft.dwLowDateTime;
      uli.HighPart = ft.dwHighDateTime;

      // Convert from Windows FILETIME (100-nanosecond intervals since Jan 1, 1601)
      // to Unix timestamp (seconds since Jan 1, 1970)
      uint64_t seconds = (uli.QuadPart / FILETIME_TICKS_PER_SECOND) - FILETIME_TO_UNIX_EPOCH_DIFF;

      return std::chrono::system_clock::from_time_t(static_cast<time_t>(seconds));
    }

    outcome::std_result<LONG> verify_file_signature(const std::wstring &wide_path)
    {
      WINTRUST_FILE_INFO file_data = {};
      file_data.cbStruct = sizeof(WINTRUST_FILE_INFO);
      file_data.pcwszFilePath = wide_path.c_str();

      GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
      WINTRUST_DATA trust_data = {};
      trust_data.cbStruct = sizeof(WINTRUST_DATA);
      trust_data.dwUIChoice = WTD_UI_NONE;
      trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
      trust_data.dwUnionChoice = WTD_CHOICE_FILE;
      trust_data.pFile = &file_data;

      LONG trust_result = WinVerifyTrust(nullptr, &policy_guid, &trust_data);

      // Clean up trust data
      trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
      WinVerifyTrust(nullptr, &policy_guid, &trust_data);

      if (trust_result == TRUST_E_NOSIGNATURE)
        {
          return outcome::failure(CertificateError::NotSigned);
        }

      return trust_result;
    }

    outcome::std_result<PCCERT_CONTEXT> find_signer_certificate(HCRYPTMSG crypt_msg, HCERTSTORE cert_store)
    {
      auto logger = unfold::utils::Logging::create("unfold:cert_extractor");

      DWORD signer_info_size = 0;
      if (CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_info_size) == FALSE)
        {
          logger->error("Failed to get signer info size");
          return outcome::failure(CertificateError::SystemError);
        }

      std::vector<BYTE> signer_info_buffer(signer_info_size);
      auto signer_info = reinterpret_cast<PCMSG_SIGNER_INFO>(signer_info_buffer.data());

      if (CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, 0, signer_info, &signer_info_size) == FALSE)
        {
          logger->error("Failed to get signer info");
          return outcome::failure(CertificateError::SystemError);
        }

      // Find the signer certificate in the store
      CERT_INFO cert_info_search = {};
      cert_info_search.Issuer = signer_info->Issuer;
      cert_info_search.SerialNumber = signer_info->SerialNumber;

      PCCERT_CONTEXT cert_context = CertFindCertificateInStore(cert_store,
                                                               X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                               0,
                                                               CERT_FIND_SUBJECT_CERT,
                                                               &cert_info_search,
                                                               nullptr);

      if (cert_context == nullptr)
        {
          logger->error("Failed to find signer certificate");
          return outcome::failure(CertificateError::SystemError);
        }

      return cert_context;
    }

    outcome::std_result<CertificateInfo> extract_certificate_info_ng(const std::wstring &wide_path)
    {
      auto logger = unfold::utils::Logging::create("unfold:cert_extractor");
      CertificateInfo cert_info;

      // Try using NCrypt/BCrypt for PE image certificate extraction
      HANDLE file_handle = CreateFileW(wide_path.c_str(),
                                       GENERIC_READ,
                                       FILE_SHARE_READ,
                                       nullptr,
                                       OPEN_EXISTING,
                                       FILE_ATTRIBUTE_NORMAL,
                                       nullptr);

      if (file_handle == INVALID_HANDLE_VALUE)
        {
          DWORD error = GetLastError();
          logger->error("Failed to open file: 0x{:x}", error);
          return outcome::failure(CertificateError::SystemError);
        }

      // Use ImageEnumerateCertificates for PE files (Next Generation approach)
      DWORD cert_count = 0;
      if (ImageEnumerateCertificates(file_handle, CERT_SECTION_TYPE_ANY, &cert_count, nullptr, 0) == FALSE)
        {
          CloseHandle(file_handle);
          DWORD error = GetLastError();
          logger->error("Failed to enumerate certificates: 0x{:x}", error);
          return outcome::failure(CertificateError::SystemError);
        }

      if (cert_count == 0)
        {
          CloseHandle(file_handle);
          return outcome::failure(CertificateError::NotSigned);
        }

      // Get the first certificate
      WIN_CERTIFICATE cert_header;

      if (ImageGetCertificateHeader(file_handle, 0, &cert_header) == FALSE)
        {
          CloseHandle(file_handle);
          DWORD error = GetLastError();
          logger->error("Failed to get certificate header: 0x{:x}", error);
          return outcome::failure(CertificateError::SystemError);
        }

      std::vector<BYTE> cert_data(cert_header.dwLength);
      auto win_cert = reinterpret_cast<LPWIN_CERTIFICATE>(cert_data.data());

      if (ImageGetCertificateData(file_handle, 0, win_cert, &cert_header.dwLength) == FALSE)
        {
          CloseHandle(file_handle);
          DWORD error = GetLastError();
          logger->error("Failed to get certificate data: 0x{:x}", error);
          return outcome::failure(CertificateError::SystemError);
        }

      CloseHandle(file_handle);

      // Decode the PKCS#7 certificate using Next Generation API
      HCRYPTMSG crypt_msg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, nullptr, nullptr);

      if (crypt_msg == nullptr)
        {
          DWORD error = GetLastError();
          logger->error("Failed to open message for decode: 0x{:x}", error);
          return outcome::failure(CertificateError::SystemError);
        }

      if (CryptMsgUpdate(crypt_msg, win_cert->bCertificate, cert_header.dwLength - offsetof(WIN_CERTIFICATE, bCertificate), TRUE)
          == FALSE)
        {
          CryptMsgClose(crypt_msg);
          DWORD error = GetLastError();
          logger->error("Failed to update message: 0x{:x}", error);
          return outcome::failure(CertificateError::SystemError);
        }

      // Get certificate store from the message
      DWORD store_size = 0;
      HCERTSTORE cert_store = nullptr;

      if (CryptMsgGetParam(crypt_msg, CMSG_CERT_PARAM, 0, nullptr, &store_size) == TRUE && store_size > 0)
        {
          std::vector<BYTE> store_data(store_size);
          if (CryptMsgGetParam(crypt_msg, CMSG_CERT_PARAM, 0, store_data.data(), &store_size) == TRUE)
            {
              CRYPT_DATA_BLOB blob;
              blob.cbData = store_size;
              blob.pbData = store_data.data();

              cert_store = CertOpenStore(CERT_STORE_PROV_PKCS7, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, &blob);
            }
        }

      if (cert_store == nullptr)
        {
          CryptMsgClose(crypt_msg);
          DWORD error = GetLastError();
          logger->error("Failed to open certificate store: 0x{:x}", error);
          return outcome::failure(CertificateError::SystemError);
        }

      // Find the signer certificate
      auto cert_result = find_signer_certificate(crypt_msg, cert_store);
      if (!cert_result)
        {
          CertCloseStore(cert_store, 0);
          CryptMsgClose(crypt_msg);
          return cert_result.error();
        }

      PCCERT_CONTEXT cert_context = cert_result.value();

      // Extract certificate details
      cert_info.subject_name = get_certificate_name_helper(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE);
      cert_info.issuer_name = get_certificate_name_helper(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE);
      cert_info.thumbprint = get_certificate_thumbprint_helper(cert_context);

      // Get serial number
      std::stringstream ss;
      for (DWORD i = 0; i < cert_context->pCertInfo->SerialNumber.cbData; i++)
        {
          const BYTE *serial_data = cert_context->pCertInfo->SerialNumber.pbData;
          DWORD reverse_index = cert_context->pCertInfo->SerialNumber.cbData - 1 - i;
          ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(serial_data[reverse_index]);
        }
      cert_info.serial_number = ss.str();

      // Get validity dates
      cert_info.not_before = filetime_to_time_point_helper(cert_context->pCertInfo->NotBefore);
      cert_info.not_after = filetime_to_time_point_helper(cert_context->pCertInfo->NotAfter);

      // Get signature algorithm (simplified)
      cert_info.signature_algorithm = "RSA"; // Could be more specific by parsing cert_context->pCertInfo->SignatureAlgorithm
      cert_info.hash_algorithm = "SHA256";   // Could be more specific

      // Cleanup
      CertFreeCertificateContext(cert_context);
      CertCloseStore(cert_store, 0);
      CryptMsgClose(crypt_msg);

      return cert_info;
    }
  } // namespace

  outcome::std_result<CertificateInfo> CertificateExtractor::extract_windows_authenticode(const std::string &file_path)
  {
    auto logger = unfold::utils::Logging::create("unfold:cert_extractor");
    CertificateInfo cert_info;

    // Convert to wide string
    std::wstring wide_path(file_path.begin(), file_path.end());

    // Step 1: Verify the signature using WinVerifyTrust
    auto trust_result = verify_file_signature(wide_path);
    cert_info.is_signed = trust_result.has_value();
    cert_info.is_valid = trust_result.has_value() && trust_result.value() == ERROR_SUCCESS;

    if (!cert_info.is_signed)
      {
        logger->info("File {} is not signed", file_path);
        return outcome::success(cert_info);
      }

    logger->info("File {} is signed, trust result: 0x{:x}", file_path, trust_result.value());

    // Step 2: Extract certificate information using Next Generation API
    auto extract_result = extract_certificate_info_ng(wide_path);
    if (!extract_result)
      {
        return extract_result.error();
      }

    cert_info = extract_result.value();
    cert_info.is_signed = true;
    cert_info.is_valid = trust_result.value() == ERROR_SUCCESS;

    logger->info("Certificate extracted successfully for {}", file_path);
    logger->info("Subject: {}", cert_info.subject_name);
    logger->info("Issuer: {}", cert_info.issuer_name);
    logger->info("Thumbprint: {}", cert_info.thumbprint);

    return outcome::success(cert_info);
  }

  std::string CertificateExtractor::get_certificate_name(PCCERT_CONTEXT cert_context, DWORD name_type)
  {
    DWORD name_size = CertGetNameStringA(cert_context, name_type, 0, nullptr, nullptr, 0);
    if (name_size <= 1)
      {
        return "";
      }

    std::vector<char> name_buffer(name_size);
    CertGetNameStringA(cert_context, name_type, 0, nullptr, name_buffer.data(), name_size);

    // Convert to string (remove null terminator)
    return std::string(name_buffer.begin(), name_buffer.end() - 1);
  }

  std::string CertificateExtractor::get_certificate_thumbprint(PCCERT_CONTEXT cert_context)
  {
    DWORD thumbprint_size = 0;
    if (CertGetCertificateContextProperty(cert_context, CERT_SHA1_HASH_PROP_ID, nullptr, &thumbprint_size) == 0)
      {
        return "";
      }

    std::vector<BYTE> thumbprint_buffer(thumbprint_size);
    if (CertGetCertificateContextProperty(cert_context, CERT_SHA1_HASH_PROP_ID, thumbprint_buffer.data(), &thumbprint_size) == 0)
      {
        return "";
      }

    std::stringstream ss;
    for (DWORD i = 0; i < thumbprint_size; i++)
      {
        ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)thumbprint_buffer[i];
      }

    return ss.str();
  }

  std::chrono::system_clock::time_point CertificateExtractor::filetime_to_time_point(const FILETIME &ft)
  {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    // Convert from Windows FILETIME (100-nanosecond intervals since Jan 1, 1601)
    // to Unix timestamp (seconds since Jan 1, 1970)
    constexpr uint64_t epoch_diff = 11644473600ULL;    // Seconds between 1601 and 1970
    constexpr uint64_t ticks_per_second = 10000000ULL; // 100-nanosecond intervals per second
    uint64_t seconds = (uli.QuadPart / ticks_per_second) - epoch_diff;

    return std::chrono::system_clock::from_time_t(static_cast<time_t>(seconds));
  }

} // namespace unfold::crypto
