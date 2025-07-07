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

#include "crypto/XMLDSigVerifier.hh"

#include <regex>
#include <memory>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/errors.h>
#include <xmlsec/openssl/app.h>
#include <xmlsec/openssl/crypto.h>

namespace
{
  constexpr size_t MAX_CERTIFICATE_SIZE = 10 * 1024; // 10KB max for certificate

  class XMLRAIIDocument
  {
  public:
    XMLRAIIDocument(const XMLRAIIDocument &) = default;
    XMLRAIIDocument(XMLRAIIDocument &&) = delete;
    XMLRAIIDocument &operator=(const XMLRAIIDocument &) = default;
    XMLRAIIDocument &operator=(XMLRAIIDocument &&) = delete;

    explicit XMLRAIIDocument(xmlDocPtr doc)
      : doc_(doc)
    {
    }
    ~XMLRAIIDocument()
    {
      if (doc_ != nullptr)
        {
          xmlFreeDoc(doc_);
        }
    }

    xmlDocPtr get() const
    {
      return doc_;
    }

  private:
    xmlDocPtr doc_;
  };

  class XMLSecRAIIContext
  {
  public:
    XMLSecRAIIContext(const XMLSecRAIIContext &) = default;
    XMLSecRAIIContext(XMLSecRAIIContext &&) = delete;
    XMLSecRAIIContext &operator=(const XMLSecRAIIContext &) = default;
    XMLSecRAIIContext &operator=(XMLSecRAIIContext &&) = delete;

    explicit XMLSecRAIIContext(xmlSecDSigCtxPtr ctx)
      : ctx_(ctx)
    {
    }
    ~XMLSecRAIIContext()
    {
      if (ctx_ != nullptr)
        {
          xmlSecDSigCtxDestroy(ctx_);
        }
    }
    xmlSecDSigCtxPtr get() const
    {
      return ctx_;
    }

  private:
    xmlSecDSigCtxPtr ctx_;
  };

} // namespace

namespace unfold::crypto
{

  const std::error_category &xmldsig_error_category()
  {
    static XMLDSigErrorCategory category;
    return category;
  }

  std::error_code make_error_code(XMLDSigError e)
  {
    return {static_cast<int>(e), xmldsig_error_category()};
  }

  class XMLDSigVerifier::Impl
  {
  public:
    Impl() = default;

    outcome::std_result<void> initialize()
    {
      xmlInitParser();
      LIBXML_TEST_VERSION;

      if (xmlSecInit() < 0)
        {
          logger_->error("xmlsec initialization failed");
          return outcome::failure(make_error_code(XMLDSigError::InitializationFailed));
        }

      if (xmlSecOpenSSLAppInit(nullptr) < 0)
        {
          xmlSecShutdown();
          logger_->error("xmlsec OpenSSL app initialization failed");
          return outcome::failure(make_error_code(XMLDSigError::InitializationFailed));
        }

      if (xmlSecOpenSSLInit() < 0)
        {
          xmlSecOpenSSLAppShutdown();
          xmlSecShutdown();
          logger_->error("xmlsec OpenSSL initialization failed");
          return outcome::failure(make_error_code(XMLDSigError::InitializationFailed));
        }

      key_manager_ = xmlSecKeysMngrCreate();
      if (key_manager_ == nullptr)
        {
          xmlSecOpenSSLShutdown();
          xmlSecOpenSSLAppShutdown();
          xmlSecShutdown();
          logger_->error("xmlsec key manager creation failed");
          return outcome::failure(make_error_code(XMLDSigError::InitializationFailed));
        }

      if (xmlSecOpenSSLAppDefaultKeysMngrInit(key_manager_) < 0)
        {
          xmlSecKeysMngrDestroy(key_manager_);
          xmlSecOpenSSLShutdown();
          xmlSecOpenSSLAppShutdown();
          xmlSecShutdown();
          logger_->error("xmlsec OpenSSL key manager initialization failed");
          return outcome::failure(make_error_code(XMLDSigError::InitializationFailed));
        }
      return outcome::success();
    }

    Impl(const Impl &) = default;
    Impl(Impl &&) = delete;
    Impl &operator=(const Impl &) = default;
    Impl &operator=(Impl &&) = delete;

    ~Impl()
    {
      if (key_manager_ != nullptr)
        {
          xmlSecKeysMngrDestroy(key_manager_);
        }

      xmlSecOpenSSLShutdown();
      xmlSecOpenSSLAppShutdown();
      xmlSecShutdown();
      xmlCleanupParser();
    }

    outcome::std_result<void> add_trusted_public_key(const std::string &key_name, const std::string &public_key_pem)
    {
      if (public_key_pem.empty())
        {
          return outcome::failure(make_error_code(XMLDSigError::InvalidKeyInfo));
        }

      if (public_key_pem.size() > MAX_CERTIFICATE_SIZE)
        {
          logger_->error("Key/certificate too large: {} bytes", public_key_pem.size());
          return outcome::failure(make_error_code(XMLDSigError::InvalidKeyInfo));
        }

      // Auto-detect format: if it looks like a certificate, use certificate format
      xmlSecKeyDataFormat format = xmlSecKeyDataFormatPem;
      if (public_key_pem.find("-----BEGIN CERTIFICATE-----") != std::string::npos)
        {
          format = xmlSecKeyDataFormatCertPem;
        }

      auto key_result = load_key_from_pem_string(public_key_pem, format);
      if (!key_result)
        {
          return key_result.error();
        }

      // Set the key name to match the KeyName in signed XML files
      if (!key_name.empty())
        {
          if (xmlSecKeySetName(key_result.value(), reinterpret_cast<const xmlChar *>(key_name.c_str())) < 0)
            {
              xmlSecKeyDestroy(key_result.value());
              logger_->error("Failed to set key name: {}", key_name);
              return outcome::failure(make_error_code(XMLDSigError::LibraryError));
            }
        }

      if (xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(key_manager_, key_result.value()) < 0)
        {
          xmlSecKeyDestroy(key_result.value());
          logger_->error("Failed to add public key to key manager");
          return outcome::failure(make_error_code(XMLDSigError::LibraryError));
        }

      return outcome::success();
    }

    outcome::std_result<void> clear_trusted_keys()
    {
      if (key_manager_ != nullptr)
        {
          xmlSecKeysMngrDestroy(key_manager_);
        }

      key_manager_ = xmlSecKeysMngrCreate();
      if (key_manager_ == nullptr)
        {
          logger_->error("xmlsec key manager creation failed during clear");
          return outcome::failure(make_error_code(XMLDSigError::LibraryError));
        }

      if (xmlSecOpenSSLAppDefaultKeysMngrInit(key_manager_) < 0)
        {
          xmlSecKeysMngrDestroy(key_manager_);
          key_manager_ = nullptr;
          logger_->error("xmlsec OpenSSL key manager initialization failed during clear");
          return outcome::failure(make_error_code(XMLDSigError::LibraryError));
        }

      logger_->info("Cleared all trusted keys from key manager");
      return outcome::success();
    }

    outcome::std_result<XMLDSigInfo> verify(const std::string &xml_content)
    {
      XMLRAIIDocument doc(xmlParseMemory(xml_content.c_str(), static_cast<int>(xml_content.size())));
      if (doc.get() == nullptr)
        {
          logger_->error("Failed to parse XML document");
          return outcome::failure(make_error_code(XMLDSigError::InvalidXML));
        }

      xmlNodePtr signature_node = xmlSecFindNode(xmlDocGetRootElement(doc.get()), xmlSecNodeSignature, xmlSecDSigNs);
      if (signature_node == nullptr)
        {
          logger_->error("No XML digital signature found");
          return outcome::failure(make_error_code(XMLDSigError::NoSignature));
        }

      auto sig_info_result = extract_signature_info(signature_node);
      if (!sig_info_result)
        {
          logger_->error("Extracted signature info is invalid");
          return outcome::failure(make_error_code(XMLDSigError::InvalidSignature));
        }

      XMLSecRAIIContext dsig_ctx(xmlSecDSigCtxCreate(key_manager_));
      if (dsig_ctx.get() == nullptr)
        {
          logger_->error("Failed to create xmlsec signature context");
          return outcome::failure(make_error_code(XMLDSigError::LibraryError));
        }

      int result = xmlSecDSigCtxVerify(dsig_ctx.get(), signature_node);
      if (result < 0)
        {
          logger_->error("XMLSec signature verification failed");
          return outcome::failure(make_error_code(XMLDSigError::VerificationFailed));
        }

      return sig_info_result.value();
    }

    outcome::std_result<XMLDSigInfo> get_signature_info(const std::string &xml_content)
    {
      XMLRAIIDocument doc(xmlParseMemory(xml_content.c_str(), static_cast<int>(xml_content.size())));
      if (doc.get() == nullptr)
        {
          logger_->error("Failed to parse XML document");
          return outcome::failure(make_error_code(XMLDSigError::InvalidXML));
        }

      xmlNodePtr signature_node = xmlSecFindNode(xmlDocGetRootElement(doc.get()), xmlSecNodeSignature, xmlSecDSigNs);
      if (signature_node == nullptr)
        {
          logger_->error("No XML digital signature found");
          return outcome::failure(make_error_code(XMLDSigError::NoSignature));
        }

      return extract_signature_info(signature_node);
    }

    static bool has_signature(const std::string &xml_content)
    {
      // Look for any Signature element with XMLDSig namespace declaration in the same element
      std::regex signature_regex(R"(<[^:]*:?Signature[^>]*xmlns[^>]*http://www\.w3\.org/2000/09/xmldsig)",
                                 std::regex_constants::icase);
      if (std::regex_search(xml_content, signature_regex))
        {
          return true;
        }

      // Look for common namespace prefixes for XMLDSig Signature elements
      std::regex prefixed_signature_regex(R"(<(ds|dsig):Signature)", std::regex_constants::icase);
      if (std::regex_search(xml_content, prefixed_signature_regex))
        {
          return true;
        }

      // Look for unprefixed Signature element in XMLDSig namespace context
      std::regex unprefixed_signature_regex(R"(<Signature[^>]*>)", std::regex_constants::icase);
      return std::regex_search(xml_content, unprefixed_signature_regex);
    }

  private:
    outcome::std_result<xmlSecKeyPtr> load_key_from_pem_string(const std::string &pem_string, xmlSecKeyDataFormat format)
    {
      xmlSecKeyPtr key = xmlSecOpenSSLAppKeyLoadMemory(reinterpret_cast<const xmlSecByte *>(pem_string.c_str()),
                                                       pem_string.size(),
                                                       format,
                                                       nullptr,
                                                       nullptr,
                                                       nullptr);

      if (key == nullptr)
        {
          logger_->error("Failed to load key from PEM string");
          return outcome::failure(make_error_code(XMLDSigError::InvalidKeyInfo));
        }

      return key;
    }

    outcome::std_result<XMLDSigInfo> extract_signature_info(xmlNodePtr signature_node)
    {
      XMLDSigInfo info;

      // Extract signature ID
      xmlChar *id = xmlGetProp(signature_node, BAD_CAST "Id");
      if (id != nullptr)
        {
          info.signature_id = reinterpret_cast<const char *>(id);
          xmlFree(id);
        }

      // Extract signature method
      xmlNodePtr sig_method_node = xmlSecFindChild(signature_node, xmlSecNodeSignedInfo, xmlSecDSigNs);
      if (sig_method_node != nullptr)
        {
          sig_method_node = xmlSecFindChild(sig_method_node, xmlSecNodeSignatureMethod, xmlSecDSigNs);
          if (sig_method_node != nullptr)
            {
              xmlChar *algorithm = xmlGetProp(sig_method_node, BAD_CAST "Algorithm");
              if (algorithm != nullptr)
                {
                  info.signature_method = reinterpret_cast<const char *>(algorithm);
                  xmlFree(algorithm);
                }
            }
        }

      // Extract canonicalization method
      xmlNodePtr signed_info_node = xmlSecFindChild(signature_node, xmlSecNodeSignedInfo, xmlSecDSigNs);
      if (signed_info_node != nullptr)
        {
          xmlNodePtr canon_method_node = xmlSecFindChild(signed_info_node, xmlSecNodeCanonicalizationMethod, xmlSecDSigNs);
          if (canon_method_node != nullptr)
            {
              xmlChar *algorithm = xmlGetProp(canon_method_node, BAD_CAST "Algorithm");
              if (algorithm != nullptr)
                {
                  info.canonicalization_method = reinterpret_cast<const char *>(algorithm);
                  xmlFree(algorithm);
                }
            }
        }

      // Extract digest method from first reference
      if (signed_info_node != nullptr)
        {
          xmlNodePtr ref_node = xmlSecFindChild(signed_info_node, xmlSecNodeReference, xmlSecDSigNs);
          if (ref_node != nullptr)
            {
              xmlNodePtr digest_method_node = xmlSecFindChild(ref_node, xmlSecNodeDigestMethod, xmlSecDSigNs);
              if (digest_method_node != nullptr)
                {
                  xmlChar *algorithm = xmlGetProp(digest_method_node, BAD_CAST "Algorithm");
                  if (algorithm != nullptr)
                    {
                      info.digest_method = reinterpret_cast<const char *>(algorithm);
                      xmlFree(algorithm);
                    }
                }
            }
        }

      // Extract X.509 certificate if present
      xmlNodePtr key_info_node = xmlSecFindChild(signature_node, xmlSecNodeKeyInfo, xmlSecDSigNs);
      if (key_info_node != nullptr)
        {
          xmlNodePtr x509_data_node = xmlSecFindChild(key_info_node, xmlSecNodeX509Data, xmlSecDSigNs);
          if (x509_data_node != nullptr)
            {
              xmlNodePtr x509_cert_node = xmlSecFindChild(x509_data_node, xmlSecNodeX509Certificate, xmlSecDSigNs);
              if (x509_cert_node != nullptr)
                {
                  xmlChar *cert_content = xmlNodeGetContent(x509_cert_node);
                  if (cert_content != nullptr)
                    {
                      info.has_x509_certificate = true;
                      info.x509_certificate = reinterpret_cast<const char *>(cert_content);
                      xmlFree(cert_content);
                    }
                }
            }
        }

      return info;
    }

    xmlSecKeysMngrPtr key_manager_ = nullptr;
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:xmldsig")};
  };

  outcome::std_result<XMLDSigVerifier> XMLDSigVerifier::create()
  {
    XMLDSigVerifier verifier;
    auto init_result = verifier.pimpl->initialize();
    if (!init_result)
      {
        return init_result.error();
      }
    return std::move(verifier);
  }

  XMLDSigVerifier::XMLDSigVerifier()
    : pimpl(std::make_unique<Impl>())
  {
  }

  XMLDSigVerifier::~XMLDSigVerifier() = default;

  XMLDSigVerifier::XMLDSigVerifier(XMLDSigVerifier &&) noexcept = default;
  XMLDSigVerifier &XMLDSigVerifier::operator=(XMLDSigVerifier &&) noexcept = default;

  outcome::std_result<void> XMLDSigVerifier::add_trusted_public_key(const std::string &key_name,
                                                                    const std::string &public_key_pem)
  {
    return pimpl->add_trusted_public_key(key_name, public_key_pem);
  }

  outcome::std_result<void> XMLDSigVerifier::clear_trusted_keys()
  {
    return pimpl->clear_trusted_keys();
  }

  outcome::std_result<XMLDSigInfo> XMLDSigVerifier::verify(const std::string &xml_content)
  {
    return pimpl->verify(xml_content);
  }

  outcome::std_result<XMLDSigInfo> XMLDSigVerifier::get_signature_info(const std::string &xml_content)
  {
    return pimpl->get_signature_info(xml_content);
  }

  bool XMLDSigVerifier::has_signature(const std::string &xml_content)
  {
    return Impl::has_signature(xml_content);
  }

} // namespace unfold::crypto
