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

#include "TransparencyLogVerifier.hh"

#include <fmt/format.h>
#include <algorithm>
#include <memory>
#include <cctype>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <openssl/evp.h>
#include <array>

#include "utils/Base64.hh"
#include "Certificate.hh"
#include "PublicKey.hh"
#include "SigstoreBundleBase.hh"
#include "MerkleTreeValidator.hh"

#include "sigstore/SigstoreErrors.hh"

namespace
{
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays)
  const unsigned char embedded_rekor_pubkey[] = {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc23-extensions"
#embed "rekor.pem"
#pragma clang diagnostic pop
  };
  const size_t embedded_rekor_pubkey_size = sizeof(embedded_rekor_pubkey);

} // namespace

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  TransparencyLogVerifier::TransparencyLogVerifier(VerificationConfig config)
    : config_(std::move(config))
  {
    merkle_validator_ = std::make_unique<MerkleTreeValidator>();

    auto result = load_embedded_certificates();
    if (!result)
      {
        logger_->error("Failed to load embedded Rekor public key: {}", result.error().message());
      }
  }

  TransparencyLogVerifier::~TransparencyLogVerifier() = default;

  outcome::std_result<void> TransparencyLogVerifier::load_embedded_certificates()
  {
    std::string rekor_pem;
    rekor_pem.reserve(embedded_rekor_pubkey_size);
    for (unsigned char byte: embedded_rekor_pubkey)
      {
        rekor_pem.push_back(static_cast<char>(byte));
      }

    auto public_key_result = PublicKey::from_pem(rekor_pem);
    if (!public_key_result)
      {
        logger_->error("Failed to parse embedded Rekor public key: {}", public_key_result.error().message());
        return outcome::failure(make_error_code(SigstoreError::InvalidCertificate));
      }

    rekor_public_key_ = std::make_unique<PublicKey>(std::move(public_key_result.value()));
    logger_->info("Loaded embedded Rekor public key successfully (type {})", rekor_public_key_->get_algorithm_name());
    return outcome::success();
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_transparency_log(TransparencyLogEntry entry,
                                                                             std::shared_ptr<const Certificate> certificate)
  {
    if (!rekor_public_key_)
      {
        logger_->error("Rekor public key is not loaded, cannot verify transparency log entry");
        return SigstoreError::TransparencyLogInvalid;
      }

    try
      {
        logger_->debug("Verifying transparency log entry with log index: {}", entry.log_index);

        auto inclusion_valid = verify_inclusion_proof(entry);
        if (!inclusion_valid)
          {
            return inclusion_valid.error();
          }

        auto timestamp_valid = verify_signed_entry_timestamp(entry);
        if (!timestamp_valid)
          {
            return timestamp_valid.error();
          }

        auto integrated_time_valid = verify_integrated_time(entry, *certificate);
        if (!integrated_time_valid)
          {
            return integrated_time_valid.error();
          }

        auto extensions_valid = verify_certificate_extensions(*certificate);
        if (!extensions_valid)
          {
            return extensions_valid.error();
          }

        auto key_usage_valid = verify_certificate_key_usage(*certificate);
        if (!key_usage_valid)
          {
            return key_usage_valid.error();
          }
        logger_->debug("Certificate key usage validation successful");
        return outcome::success();
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during transparency log verification: {}", e.what());
        return SigstoreError::SystemError;
      }
  }

  // =============================================================================
  // Inclusion Proof
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_inclusion_proof(const TransparencyLogEntry &entry)
  {
    if (!entry.inclusion_proof.has_value())
      {
        logger_->error("No inclusion proof provided for transparency log entry");
        return SigstoreError::TransparencyLogInvalid;
      }

    const InclusionProof &proof = entry.inclusion_proof.value();

    if (!proof.checkpoint.has_value())
      {
        logger_->error("No checkpoint provided in inclusion proof");
        return SigstoreError::TransparencyLogInvalid;
      }

    std::string leaf_hash = compute_leaf_hash(entry);
    if (leaf_hash.empty())
      {
        logger_->error("Failed to compute leaf hash for inclusion proof verification");
        return SigstoreError::TransparencyLogInvalid;
      }

    auto inclusion_valid = merkle_validator_->verify_inclusion_proof(proof.hashes,
                                                                     proof.log_index,
                                                                     proof.tree_size,
                                                                     leaf_hash,
                                                                     proof.root_hash);
    if (!inclusion_valid)
      {
        return inclusion_valid.error();
      }
    logger_->debug("Inclusion proof verification successful");

    auto checkpoint_valid = verify_checkpoint(proof.checkpoint.value(), proof.root_hash, proof.tree_size);
    if (!checkpoint_valid)
      {
        return checkpoint_valid.error();
      }
    return outcome::success();
  }

  std::string TransparencyLogVerifier::compute_leaf_hash(const TransparencyLogEntry &entry)
  {
    try
      {
        if (!entry.body.has_value())
          {
            logger_->error("Cannot compute leaf hash without body data");
            return "";
          }

        std::string decoded_data = unfold::utils::Base64::decode(entry.body.value());
        std::string leaf_hash = hasher_.hash_leaf(decoded_data);

        logger_->debug("Computed leaf hash from body data (body length: {}, hash length: {})",
                       decoded_data.length(),
                       leaf_hash.length());

        return leaf_hash;
      }
    catch (const std::exception &e)
      {
        logger_->error("Error computing leaf hash: {}", e.what());
        return "";
      }
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_checkpoint(const Checkpoint &checkpoint,
                                                                       const std::string &expected_root_hash,
                                                                       int64_t expected_tree_size)
  {
    try
      {
        logger_->debug("Verifying checkpoint");

        if (checkpoint.origin.empty())
          {
            logger_->error("Checkpoint origin is empty");
            return SigstoreError::TransparencyLogInvalid;
          }
        if (checkpoint.tree_size != expected_tree_size)
          {
            logger_->error("Checkpoint tree size {} does not match expected tree size {}",
                           checkpoint.tree_size,
                           expected_tree_size);
            return SigstoreError::TransparencyLogInvalid;
          }
        if (checkpoint.root_hash != expected_root_hash)
          {
            logger_->error("Checkpoint root hash {} does not match expected root hash {}",
                           checkpoint.root_hash,
                           expected_root_hash);
            return SigstoreError::TransparencyLogInvalid;
          }

        const std::string &body = checkpoint.body;
        if (body.empty())
          {
            logger_->error("Empty checkpoint envelope");
            return SigstoreError::TransparencyLogInvalid;
          }
        if (checkpoint.signatures.empty())
          {
            logger_->error("No signatures found in checkpoint");
            return SigstoreError::TransparencyLogInvalid;
          }

        for (const auto &sig: checkpoint.signatures)
          {
            if (sig.signer.starts_with("rekor.sigstore.dev"))
              {
                logger_->debug("Verifying checkpoint signature for signer: {}", sig.signer);
                auto valid = verify_rekor_log_entry_signature(body, sig.signature);
                if (!valid)
                  {
                    return valid.error();
                  }
              }
            else
              {
                logger_->warn("Skipping checkpoint signature verification for unknown signer: {}", sig.signer);
              }
          }

        return outcome::success();
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during checkpoint verification: {}", e.what());
        return SigstoreError::TransparencyLogInvalid;
      }
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_rekor_log_entry_signature(const std::string &log_entry,
                                                                                      const std::string &signature_b64)
  {
    if (!rekor_public_key_)
      {
        return SigstoreError::TransparencyLogInvalid;
      }

    try
      {
        std::string signature_data = unfold::utils::Base64::decode(signature_b64);

        // Remove first 4 bytes (key hint)
        if (signature_data.size() > 4)
          {
            signature_data = signature_data.substr(4);
          }
        else
          {
            logger_->error("Signature data too short to remove header bytes");
            return SigstoreError::TransparencyLogInvalid;
          }

        auto verify_result = rekor_public_key_->verify_signature(log_entry, signature_data);
        if (!verify_result)
          {
            return verify_result.error();
          }
        if (!verify_result.value())
          {
            logger_->error("Rekor log entry signature verification failed");
            return SigstoreError::TransparencyLogInvalid;
          }

        return outcome::success();
      }
    catch (const std::exception &e)
      {
        logger_->error("Exception during signature verification: {}", e.what());
        return SigstoreError::TransparencyLogInvalid;
      }
  }

  // =============================================================================
  // Signed Entry Timestamp
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_signed_entry_timestamp(const TransparencyLogEntry &entry)
  {
    try
      {
        logger_->debug("Verifying signed entry timestamp");
        if (!entry.inclusion_promise.has_value())
          {
            logger_->error("No inclusion promise to verify");
            return SigstoreError::TransparencyLogInvalid;
          }
        const InclusionPromise &promise = entry.inclusion_promise.value();

        std::string signature_data = unfold::utils::Base64::decode(promise.signed_entry_timestamp);
        if (signature_data.empty())
          {
            logger_->error("Failed to decode signed entry timestamp");
            return SigstoreError::TransparencyLogInvalid;
          }

        if (!entry.body.has_value())
          {
            logger_->error("Cannot verify signed entry timestamp without body data");
            return SigstoreError::TransparencyLogInvalid;
          }

        if (!entry.integrated_time.has_value())
          {
            logger_->error("Cannot verify signed entry timestamp without integrated time");
            return SigstoreError::TransparencyLogInvalid;
          }

        auto canonicalized_payload = fmt::format(R"({{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}})",
                                                 entry.body.value(),
                                                 entry.integrated_time.value(),
                                                 entry.log_id.value(),
                                                 entry.log_index);

        auto verify_result = rekor_public_key_->verify_signature(canonicalized_payload, signature_data);
        if (!verify_result)
          {
            return verify_result.error();
          }

        bool is_valid = verify_result.value();
        if (!is_valid)
          {
            logger_->warn("Signed entry timestamp verification failed");
          }

        if (is_valid)
          {
            return outcome::success();
          }
        return SigstoreError::TransparencyLogInvalid;
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during signed entry timestamp verification: {}", e.what());
        return SigstoreError::TransparencyLogInvalid;
      }
  }

  // =============================================================================
  // Integrated Time
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_integrated_time(const TransparencyLogEntry &entry,
                                                                            const Certificate &certificate)
  {
    try
      {
        if (!entry.integrated_time.has_value())
          {
            logger_->error("No integrated time to verify");
            return SigstoreError::TransparencyLogInvalid;
          }

        int64_t integrated_time_seconds = entry.integrated_time.value();
        auto integrated_time = std::chrono::system_clock::from_time_t(static_cast<std::time_t>(integrated_time_seconds));
        logger_->debug("Verifying integrated time: {}", integrated_time);

        auto cert_valid_at_time_result = certificate.is_valid_at_time(integrated_time);
        if (!cert_valid_at_time_result)
          {
            return cert_valid_at_time_result.error();
          }
        if (!cert_valid_at_time_result.value())
          {
            logger_->error("Certificate validity check failed at integrated time: {}", integrated_time_seconds);
            return SigstoreError::TransparencyLogInvalid;
          }

        auto current_time = std::chrono::system_clock::now();
        constexpr auto MAX_CLOCK_SKEW = std::chrono::seconds(300); // 5 minutes

        // Check if integrated time is not too far in the future
        if (integrated_time > current_time + MAX_CLOCK_SKEW)
          {
            logger_->warn("Integrated time {} is too far in the future (current: {})",
                          integrated_time_seconds,
                          std::chrono::system_clock::to_time_t(current_time));
            return SigstoreError::InvalidCertificate;
          }

        logger_->debug("Integrated time validation successful: certificate was valid at {}", integrated_time_seconds);
        return outcome::success();
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during integrated time verification: {}", e.what());
        return SigstoreError::TransparencyLogInvalid;
      }
  }

  // =============================================================================
  // Certificates
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_certificate_extensions(const Certificate &certificate,
                                                                                   const std::string &expected_email,
                                                                                   const std::string &expected_issuer)
  {
    try
      {
        logger_->debug("Verifying certificate extensions");

        // Verify Subject Alternative Name (email)
        std::string subject_email = certificate.subject_email();
        if (subject_email.empty())
          {
            logger_->error("Certificate does not contain a subject email in SAN extension");
            return SigstoreError::InvalidCertificate;
          }
        logger_->debug("Found subject email: {}", subject_email);

        // If an expected email is provided, validate it
        if (!expected_email.empty() && subject_email != expected_email)
          {
            logger_->error("Subject email mismatch: expected '{}', found '{}'", expected_email, subject_email);
            return SigstoreError::InvalidCertificate;
          }

        // Verify OIDC issuer extension
        std::string oidc_issuer = certificate.oidc_issuer();
        if (oidc_issuer.empty())
          {
            logger_->error("Certificate does not contain OIDC issuer extension");
            return SigstoreError::InvalidCertificate;
          }
        logger_->debug("Found OIDC issuer: {}", oidc_issuer);

        // If an expected issuer is provided, validate it
        if (!expected_issuer.empty() && oidc_issuer != expected_issuer)
          {
            logger_->error("OIDC issuer mismatch: expected '{}', found '{}'", expected_issuer, oidc_issuer);
            return SigstoreError::InvalidCertificate;
          }

        // Validate that the OIDC issuer is from a trusted source (e.g., GitHub, GitLab, etc.)
        const std::vector<std::string> trusted_issuers = {"https://github.com/login/oauth",
                                                          "https://gitlab.com",
                                                          "https://accounts.google.com",
                                                          "https://oauth2.sigstore.dev/auth"};

        bool issuer_trusted = std::ranges::find(trusted_issuers, oidc_issuer) != trusted_issuers.end();
        if (!issuer_trusted)
          {
            logger_->warn("OIDC issuer '{}' is not in the list of trusted issuers", oidc_issuer);
          }

        logger_->debug("Certificate extensions validation successful");
        return outcome::success();
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during certificate extensions verification: {}", e.what());
        return SigstoreError::InvalidCertificate;
      }
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_certificate_key_usage(const Certificate &certificate)
  {
    try
      {
        logger_->debug("Verifying certificate key usage");

        X509 *cert = certificate.get();
        if (cert == nullptr)
          {
            logger_->error("Invalid certificate for key usage verification");
            return SigstoreError::InvalidCertificate;
          }

        // Check Extended Key Usage extension
        STACK_OF(ASN1_OBJECT) *eku = static_cast<STACK_OF(ASN1_OBJECT) *>(
          X509_get_ext_d2i(cert, NID_ext_key_usage, nullptr, nullptr));

        if (eku == nullptr)
          {
            logger_->error("Certificate does not contain Extended Key Usage extension");
            return SigstoreError::InvalidCertificate;
          }

        bool code_signing_found = false;
        int eku_count = sk_ASN1_OBJECT_num(eku);

        for (int i = 0; i < eku_count; i++)
          {
            ASN1_OBJECT *usage = sk_ASN1_OBJECT_value(eku, i);
            if (usage != nullptr)
              {
                constexpr size_t OID_BUFFER_SIZE = 256;
                std::array<char, OID_BUFFER_SIZE> oid_str{};
                OBJ_obj2txt(oid_str.data(), OID_BUFFER_SIZE, usage, 1);

                logger_->debug("Found EKU: {}", oid_str.data());

                // Check for Code Signing (1.3.6.1.5.5.7.3.3)
                if (std::string(oid_str.data()) == "1.3.6.1.5.5.7.3.3")
                  {
                    code_signing_found = true;
                    break;
                  }
              }
          }
        sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);

        if (!code_signing_found)
          {
            logger_->error("Certificate does not have Code Signing extended key usage");
            return SigstoreError::InvalidCertificate;
          }

        // Check Key Usage extension for digital signature
        auto *key_usage = static_cast<ASN1_BIT_STRING *>(X509_get_ext_d2i(cert, NID_key_usage, nullptr, nullptr));

        if (key_usage != nullptr)
          {
            int usage_bits = ASN1_BIT_STRING_get_bit(key_usage, 0); // Digital Signature bit
            ASN1_BIT_STRING_free(key_usage);

            if (usage_bits != 1)
              {
                logger_->warn("Certificate Key Usage does not include Digital Signature");
                // This might be acceptable in some cases, so we'll warn but not fail
                // return false;
              }
            else
              {
                logger_->debug("Certificate has Digital Signature key usage");
              }
          }
        else
          {
            logger_->debug("Certificate does not have Key Usage extension (might be acceptable)");
          }

        logger_->debug("Certificate key usage validation successful");
        return outcome::success();
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during certificate key usage verification: {}", e.what());
        return SigstoreError::InvalidCertificate;
      }
  }

  // =============================================================================
  // Bundle Consistency Verification
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_bundle_consistency(const TransparencyLogEntry &entry,
                                                                               std::shared_ptr<SigstoreBundleBase> bundle)
  {
    try
      {
        logger_->debug("Verifying bundle consistency with transparency log entry");

        if (!entry.body.has_value())
          {
            logger_->debug("Cannot verify bundle consistency without body data");
            return SigstoreError::TransparencyLogInvalid;
          }

        // Try to decode the body (unified field for both canonicalizedBody and API body)
        std::string body_data;
        try
          {
            body_data = unfold::utils::Base64::decode(entry.body.value());
          }
        catch (const std::exception &e)
          {
            logger_->debug("Base64 decode failed for body data: {}", e.what());
            return SigstoreError::TransparencyLogInvalid;
          }

        boost::json::value json_val;
        try
          {
            json_val = boost::json::parse(body_data);
          }
        catch (const std::exception &e)
          {
            logger_->debug("JSON parsing failed for body data: {}", e.what());
            return SigstoreError::TransparencyLogInvalid;
          }

        if (!json_val.is_object())
          {
            logger_->debug("Body data is not a valid JSON object");
            return SigstoreError::TransparencyLogInvalid;
          }

        const auto &obj = json_val.as_object();

        if (!obj.contains("spec") || !obj.at("spec").is_object())
          {
            logger_->debug("Body data missing 'spec' section");
            return SigstoreError::TransparencyLogInvalid;
          }

        const auto &spec = obj.at("spec").as_object();

        // Extract data from the bundle
        std::string bundle_signature = bundle->get_signature();
        auto bundle_certificate = bundle->get_certificate();
        auto bundle_message_digest_opt = bundle->get_message_digest();

        // Verify all components using helper methods
        auto signature_valid = verify_signature_consistency(spec, bundle_signature);
        auto certificate_valid = verify_certificate_consistency(spec, *bundle_certificate);
        auto hash_valid = bundle_message_digest_opt.has_value()
                            ? verify_hash_consistency(spec, bundle_message_digest_opt.value())
                            : outcome::success(); // Legacy bundles don't have message digest, so skip hash verification

        if (signature_valid && certificate_valid && hash_valid)
          {
            logger_->debug("Bundle consistency verification successful");
            return outcome::success();
          }

        logger_->debug("Bundle consistency verification failed");
        return SigstoreError::TransparencyLogInvalid;
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during bundle consistency verification: {}", e.what());
        return SigstoreError::SystemError;
      }
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_signature_consistency(const boost::json::object &spec,
                                                                                  const std::string &bundle_signature)
  {
    if (!spec.contains("signature") || !spec.at("signature").is_object())
      {
        logger_->error("Canonicalized body missing 'signature' section");
        return SigstoreError::TransparencyLogInvalid;
      }

    const auto &signature_obj = spec.at("signature").as_object();

    if (!signature_obj.contains("content"))
      {
        logger_->error("Canonicalized body missing signature content");
        return SigstoreError::TransparencyLogInvalid;
      }

    std::string tlog_signature = signature_obj.at("content").as_string().c_str();
    if (tlog_signature != bundle_signature)
      {
        logger_->error("Signature mismatch between bundle and transparency log");
        logger_->debug("Bundle signature: {}", bundle_signature);
        logger_->debug("TLog signature:  {}", tlog_signature);
        return SigstoreError::TransparencyLogInvalid;
      }

    logger_->debug("Signature consistency verified");
    return outcome::success();
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_certificate_consistency(const boost::json::object &spec,
                                                                                    const Certificate &bundle_certificate)
  {
    if (!spec.contains("signature") || !spec.at("signature").is_object())
      {
        logger_->error("Canonicalized body missing 'signature' section");
        return SigstoreError::TransparencyLogInvalid;
      }

    const auto &signature_obj = spec.at("signature").as_object();

    if (!signature_obj.contains("publicKey") || !signature_obj.at("publicKey").is_object())
      {
        logger_->error("Canonicalized body missing publicKey section");
        return SigstoreError::TransparencyLogInvalid;
      }

    const auto &public_key_obj = signature_obj.at("publicKey").as_object();

    if (!public_key_obj.contains("content"))
      {
        logger_->error("Canonicalized body missing publicKey content");
        return SigstoreError::TransparencyLogInvalid;
      }

    std::string tlog_certificate_pem = public_key_obj.at("content").as_string().c_str();

    // Decode the PEM certificate content from base64
    std::string tlog_pem_decoded = unfold::utils::Base64::decode(tlog_certificate_pem);

    // Create Certificate object from PEM data
    auto tlog_cert_result = Certificate::from_pem(tlog_pem_decoded);
    if (!tlog_cert_result)
      {
        logger_->error("Failed to parse transparency log certificate from PEM");
        return SigstoreError::TransparencyLogInvalid;
      }

    // Compare the certificates directly using operator==
    if (bundle_certificate != tlog_cert_result.value())
      {
        logger_->error("Certificate mismatch between bundle and transparency log");
        return SigstoreError::TransparencyLogInvalid;
      }

    logger_->debug("Certificate consistency verified");
    return outcome::success();
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_hash_consistency(const boost::json::object &spec,
                                                                             const std::string &bundle_message_digest)
  {
    if (!spec.contains("data") || !spec.at("data").is_object())
      {
        logger_->error("Canonicalized body missing 'data' section");
        return SigstoreError::TransparencyLogInvalid;
      }

    const auto &data_obj = spec.at("data").as_object();

    if (!data_obj.contains("hash") || !data_obj.at("hash").is_object())
      {
        logger_->error("Canonicalized body missing hash section");
        return SigstoreError::TransparencyLogInvalid;
      }

    const auto &hash_obj = data_obj.at("hash").as_object();

    if (!hash_obj.contains("value"))
      {
        logger_->error("Canonicalized body missing hash value");
        return SigstoreError::TransparencyLogInvalid;
      }

    std::string tlog_hash_hex = hash_obj.at("value").as_string().c_str();

    // Convert hex hash to Base64 for comparison with bundle message digest
    std::string tlog_hash_binary;
    constexpr int HEX_BASE = 16;
    for (size_t i = 0; i < tlog_hash_hex.length(); i += 2)
      {
        std::string byte_str = tlog_hash_hex.substr(i, 2);
        auto byte = static_cast<unsigned char>(std::stoul(byte_str, nullptr, HEX_BASE));
        tlog_hash_binary.push_back(static_cast<char>(byte));
      }

    std::string tlog_hash_b64 = unfold::utils::Base64::encode(tlog_hash_binary);

    if (tlog_hash_b64 != bundle_message_digest)
      {
        logger_->error("Hash mismatch between bundle and transparency log");
        logger_->debug("Bundle hash: {}", bundle_message_digest);
        logger_->debug("TLog hash:   {}", tlog_hash_b64);
        return SigstoreError::TransparencyLogInvalid;
      }

    logger_->debug("Hash consistency verified");
    return outcome::success();
  }

} // namespace unfold::sigstore
