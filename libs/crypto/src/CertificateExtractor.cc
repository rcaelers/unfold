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

#include <bcrypt.h>
#include <imagehlp.h>
#include <iomanip>
#include <iostream>
#include <mscat.h>
#include <ncrypt.h>
#include <softpub.h>
#include <sstream>
#include <wincrypt.h>
#include <windows.h>
#include <wintrust.h>

namespace
{
  constexpr uint64_t FILETIME_TO_UNIX_EPOCH_DIFF = 11644473600ULL; // Seconds between 1601 and 1970
  constexpr uint64_t FILETIME_TICKS_PER_SECOND = 10000000ULL;      // 100-nanosecond intervals per second
} // namespace

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

  outcome::std_result<LONG> CertificateExtractor::verify_file_signature(const std::wstring &wide_path)
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

  outcome::std_result<PCCERT_CONTEXT> CertificateExtractor::find_signer_certificate(HCRYPTMSG crypt_msg, HCERTSTORE cert_store)
  {
    DWORD signer_info_size = 0;
    if (CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_info_size) == FALSE)
      {
        logger->error("Failed to get signer info size");
        return outcome::failure(CertificateError::SystemError);
      }

    std::vector<BYTE> signer_info_buffer(signer_info_size);
    auto *signer_info = reinterpret_cast<PCMSG_SIGNER_INFO>(signer_info_buffer.data());

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

  outcome::std_result<CertificateInfo> CertificateExtractor::extract_certificate_info_ng(const std::wstring &wide_path)
  {
    CertificateInfo cert_info;

    // Try using NCrypt/BCrypt for PE image certificate extraction
    HANDLE file_handle = CreateFileW(wide_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

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
    auto *win_cert = reinterpret_cast<LPWIN_CERTIFICATE>(cert_data.data());

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

    if (CryptMsgUpdate(crypt_msg, win_cert->bCertificate, cert_header.dwLength - offsetof(WIN_CERTIFICATE, bCertificate), TRUE) == FALSE)
      {
        CryptMsgClose(crypt_msg);
        DWORD error = GetLastError();
        logger->error("Failed to update message: 0x{:x}", error);
        return outcome::failure(CertificateError::SystemError);
      }

    // Get certificate store from the message
    HCERTSTORE cert_store = nullptr;

    logger->info("Getting certificate store from message");

    cert_store = CertOpenStore(CERT_STORE_PROV_MSG, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, crypt_msg);
    if (cert_store == nullptr)
      {
        // If that fails, try the PKCS7 approach as a fallback
        DWORD store_size = 0;
        if (CryptMsgGetParam(crypt_msg, CMSG_CERT_PARAM, 0, nullptr, &store_size) == TRUE && store_size > 0)
          {
            logger->info("Certificate store size: {}", store_size);
            std::vector<BYTE> store_data(store_size);
            if (CryptMsgGetParam(crypt_msg, CMSG_CERT_PARAM, 0, store_data.data(), &store_size) == TRUE)
              {
                CRYPT_DATA_BLOB blob;
                blob.cbData = store_size;
                blob.pbData = store_data.data();
                logger->info("Opening certificate store from blob as fallback");

                cert_store = CertOpenStore(CERT_STORE_PROV_SERIALIZED, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, &blob);
              }
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
    cert_info.subject_name = get_certificate_name(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE);
    cert_info.issuer_name = get_certificate_name(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, true); // true for issuer
    cert_info.thumbprint = get_certificate_thumbprint(cert_context);

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
    cert_info.not_before = filetime_to_time_point(cert_context->pCertInfo->NotBefore);
    cert_info.not_after = filetime_to_time_point(cert_context->pCertInfo->NotAfter);

    // Get actual signature algorithm from certificate
    cert_info.signature_algorithm = get_signature_algorithm(cert_context->pCertInfo->SignatureAlgorithm.pszObjId);
    logger->info("Detected signature algorithm: {} (OID: {})",
                 cert_info.signature_algorithm,
                 cert_context->pCertInfo->SignatureAlgorithm.pszObjId != nullptr ? cert_context->pCertInfo->SignatureAlgorithm.pszObjId : "null");

    // Get actual hash algorithm directly from the cryptographic message
    DWORD hash_oid_size = 0;
    if (CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &hash_oid_size) == TRUE && hash_oid_size > 0)
      {
        std::vector<BYTE> hash_info_buffer(hash_oid_size);
        auto *hash_signer_info = reinterpret_cast<PCMSG_SIGNER_INFO>(hash_info_buffer.data());

        if (CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, 0, hash_signer_info, &hash_oid_size) == TRUE)
          {
            cert_info.hash_algorithm = get_hash_algorithm(hash_signer_info->HashAlgorithm.pszObjId);
            logger->info("Detected hash algorithm: {} (OID: {})",
                         cert_info.hash_algorithm,
                         hash_signer_info->HashAlgorithm.pszObjId != nullptr ? hash_signer_info->HashAlgorithm.pszObjId : "null");
          }
        else
          {
            cert_info.hash_algorithm = "Unknown"; // fallback
            logger->warn("Failed to get hash algorithm, using fallback: Unknown");
          }
      }
    else
      {
        cert_info.hash_algorithm = "Unknown"; // fallback
        logger->warn("No hash algorithm info available, using fallback: Unknown");
      }

    // Extract certificate chain
    cert_info.certificate_chain = extract_certificate_chain(cert_store);
    logger->info("Certificate chain contains {} certificates", cert_info.certificate_chain.size());

    // Cleanup
    CertFreeCertificateContext(cert_context);
    CertCloseStore(cert_store, 0);
    CryptMsgClose(crypt_msg);

    return cert_info;
  }
  std::string CertificateExtractor::get_certificate_name(PCCERT_CONTEXT cert_context, DWORD name_type, bool is_issuer)
  {
    DWORD flags = is_issuer ? CERT_NAME_ISSUER_FLAG : 0;
    DWORD name_size = CertGetNameStringA(cert_context, name_type, flags, nullptr, nullptr, 0);
    if (name_size <= 1)
      {
        return "";
      }

    std::vector<char> name_buffer(name_size);
    CertGetNameStringA(cert_context, name_type, flags, nullptr, name_buffer.data(), name_size);
    return {name_buffer.begin(), name_buffer.end() - 1};
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
    uint64_t seconds = (uli.QuadPart / FILETIME_TICKS_PER_SECOND) - FILETIME_TO_UNIX_EPOCH_DIFF;

    return std::chrono::system_clock::from_time_t(static_cast<time_t>(seconds));
  }

  std::string CertificateExtractor::get_signature_algorithm(const char *oid)
  {
    if (oid == nullptr)
      {
        return "Unknown";
      }

    std::string oid_str(oid);

    // Common signature algorithm OIDs
    if (oid_str == "1.2.840.113549.1.1.11")
      {
        return "RSA-SHA256";
      }
    if (oid_str == "1.2.840.113549.1.1.5")
      {
        return "RSA-SHA1";
      }
    if (oid_str == "1.2.840.113549.1.1.12")
      {
        return "RSA-SHA384";
      }
    if (oid_str == "1.2.840.113549.1.1.13")
      {
        return "RSA-SHA512";
      }
    if (oid_str == "1.2.840.113549.1.1.10")
      {
        return "RSA-PSS";
      }
    if (oid_str == "1.2.840.10045.4.3.2")
      {
        return "ECDSA-SHA256";
      }
    if (oid_str == "1.2.840.10045.4.3.3")
      {
        return "ECDSA-SHA384";
      }
    if (oid_str == "1.2.840.10045.4.3.4")
      {
        return "ECDSA-SHA512";
      }
    if (oid_str == "1.2.840.10045.4.1")
      {
        return "ECDSA-SHA1";
      }

    return "Unknown"; // Default fallback
  }

  std::string CertificateExtractor::get_hash_algorithm(const char *oid)
  {
    if (oid == nullptr)
      {
        return "Unknown";
      }

    std::string oid_str(oid);

    // Common hash algorithm OIDs
    if (oid_str == "2.16.840.1.101.3.4.2.1")
      {
        return "SHA256";
      }
    if (oid_str == "1.3.14.3.2.26")
      {
        return "SHA1";
      }
    if (oid_str == "2.16.840.1.101.3.4.2.2")
      {
        return "SHA384";
      }
    if (oid_str == "2.16.840.1.101.3.4.2.3")
      {
        return "SHA512";
      }
    if (oid_str == "1.2.840.113549.2.5")
      {
        return "MD5";
      }

    return "Unknown"; // Default fallback
  }

  std::vector<std::string> CertificateExtractor::extract_certificate_chain(HCERTSTORE cert_store)
  {
    std::vector<std::string> chain;

    if (cert_store == nullptr)
      {
        return chain;
      }

    // First, enumerate all certificates directly in the PKCS#7 store
    logger->info("Certificates directly embedded in PKCS#7:");
    PCCERT_CONTEXT cert_context = nullptr;
    PCCERT_CONTEXT signer_cert = nullptr;

    while ((cert_context = CertEnumCertificatesInStore(cert_store, cert_context)) != nullptr)
      {
        std::string subject_name = get_certificate_name(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE);
        std::string issuer_name = get_certificate_name(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, true);
        logger->info("  Subject: {} | Issuer: {}", subject_name, issuer_name);

        // Keep the first certificate as potential signer
        if (signer_cert == nullptr)
          {
            signer_cert = CertDuplicateCertificateContext(cert_context);
          }
      }

    // Now try to build the complete chain using Windows certificate chain engine
    if (signer_cert != nullptr)
      {
        logger->info("Building certificate chain using Windows chain engine:");

        // Set up chain parameters
        CERT_CHAIN_PARA chain_para = {};
        chain_para.cbSize = sizeof(CERT_CHAIN_PARA);

        PCCERT_CHAIN_CONTEXT chain_context = nullptr;
        BOOL chain_result = CertGetCertificateChain(nullptr,         // use default chain engine
                                                    signer_cert,     // starting certificate
                                                    nullptr,         // use current time
                                                    cert_store,      // additional store to search
                                                    &chain_para,     // chain parameters
                                                    0,               // flags
                                                    nullptr,         // reserved
                                                    &chain_context); // output chain context
        if (chain_result != FALSE)
          {
            // Extract certificates from the built chain
            for (DWORD i = 0; i < chain_context->cChain; i++)
              {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                PCERT_SIMPLE_CHAIN simple_chain = chain_context->rgpChain[i];
                for (DWORD j = 0; j < simple_chain->cElement; j++)
                  {
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
                    PCERT_CHAIN_ELEMENT element = simple_chain->rgpElement[j];
                    std::string subject = get_certificate_name(element->pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE);
                    std::string issuer = get_certificate_name(element->pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, true);

                    chain.push_back(subject);
                    logger->info("  Chain[{}][{}]: {} (issued by: {})", i, j, subject, issuer);
                  }
              }

            CertFreeCertificateChain(chain_context);
          }
        else
          {
            DWORD error = GetLastError();
            logger->warn("Failed to build certificate chain: 0x{:x}", error);

            // Fallback: just add the signer certificate
            std::string subject_name = get_certificate_name(signer_cert, CERT_NAME_SIMPLE_DISPLAY_TYPE);
            if (!subject_name.empty())
              {
                chain.push_back(subject_name);
                logger->info("Fallback: added signer certificate: {}", subject_name);
              }
          }

        CertFreeCertificateContext(signer_cert);
      }

    return chain;
  }

  outcome::std_result<CertificateInfo> CertificateExtractor::extract_windows_authenticode(const std::string &file_path)
  {
    CertificateInfo cert_info;

    std::wstring wide_path(file_path.begin(), file_path.end());

    // Step 1: Verify the signature using WinVerifyTrust
    auto trust_result = verify_file_signature(wide_path);

    // Handle different WinVerifyTrust results
    if (!trust_result.has_value())
      {
        // This handles TRUST_E_NOSIGNATURE (not signed)
        if (trust_result.error() == make_error_code(CertificateError::NotSigned))
          {
            logger->info("File {} is not signed", file_path);
            cert_info.is_signed = false;
            cert_info.is_valid = false;
            return outcome::success(cert_info);
          }
        // Other certificate-related errors
        return trust_result.error();
      }

    LONG trust_value = trust_result.value();
    logger->info("WinVerifyTrust result for {}: 0x{:x}", file_path, static_cast<DWORD>(trust_value));

    // Check for file access errors that WinVerifyTrust might return
    constexpr LONG CRYPT_E_FILE_ERROR_HRESULT = static_cast<LONG>(0x80092003);
    if (trust_value == CRYPT_E_FILE_ERROR_HRESULT)
      {
        logger->error("File {} not found or inaccessible", file_path);
        return outcome::failure(CertificateError::SystemError);
      }

    cert_info.is_signed = true;
    cert_info.is_valid = (trust_value == ERROR_SUCCESS);

    logger->info("File {} is signed", file_path);

    if (cert_info.is_valid)
      {
        logger->info("File {} is trusted", file_path);
      }

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

} // namespace unfold::crypto
