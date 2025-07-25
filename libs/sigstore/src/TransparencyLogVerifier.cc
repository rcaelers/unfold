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

#include "BundleHelper.hh"
#include "utils/Base64.hh"
#include "Certificate.hh"
#include "PublicKey.hh"
#include "MerkleTreeValidator.hh"
#include "CheckpointParser.hh"
#include "CanonicalBodyParser.hh"

#include "sigstore/SigstoreErrors.hh"

#include "sigstore_rekor.pb.h"

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

    [[maybe_unused]] auto result = load_embedded_certificates();
  }

  TransparencyLogVerifier::~TransparencyLogVerifier() = default;

  outcome::std_result<void> TransparencyLogVerifier::load_embedded_certificates()
  {
    std::string rekor_pem;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    rekor_pem.assign(reinterpret_cast<const char *>(embedded_rekor_pubkey), embedded_rekor_pubkey_size);

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

  outcome::std_result<void> TransparencyLogVerifier::verify_transparency_log(dev::sigstore::rekor::v1::TransparencyLogEntry entry,
                                                                             const Certificate &certificate)
  {
    try
      {
        logger_->debug("Verifying transparency log entry with log index: {}", entry.log_index());

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

        auto integrated_time_valid = verify_integrated_time(entry, certificate);
        if (!integrated_time_valid)
          {
            return integrated_time_valid.error();
          }

        auto extensions_valid = verify_certificate_extensions(certificate);
        if (!extensions_valid)
          {
            return extensions_valid.error();
          }

        auto key_usage_valid = verify_certificate_key_usage(certificate);
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

  outcome::std_result<void> TransparencyLogVerifier::verify_inclusion_proof(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry)
  {
    if (!entry.has_inclusion_proof())
      {
        logger_->error("No inclusion proof provided for transparency log entry");
        return SigstoreError::InvalidTransparencyLog;
      }

    const dev::sigstore::rekor::v1::InclusionProof &proof = entry.inclusion_proof();

    if (!proof.has_checkpoint())
      {
        logger_->error("No checkpoint provided in inclusion proof");
        return SigstoreError::InvalidTransparencyLog;
      }

    std::string leaf_hash = compute_leaf_hash(entry);
    if (leaf_hash.empty())
      {
        logger_->error("Failed to compute leaf hash for inclusion proof verification");
        return SigstoreError::InvalidTransparencyLog;
      }

    auto inclusion_valid = merkle_validator_->verify_inclusion_proof(proof.hashes(),
                                                                     proof.log_index(),
                                                                     proof.tree_size(),
                                                                     leaf_hash,
                                                                     proof.root_hash());
    if (!inclusion_valid)
      {
        return inclusion_valid.error();
      }

    auto checkpoint_valid = verify_checkpoint(proof.checkpoint(), proof.root_hash(), proof.tree_size());
    if (!checkpoint_valid)
      {
        return checkpoint_valid.error();
      }
    return outcome::success();
  }

  std::string TransparencyLogVerifier::compute_leaf_hash(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry)
  {
    try
      {
        if (entry.canonicalized_body().empty())
          {
            logger_->error("Cannot compute leaf hash without body data");
            return "";
          }

        return hasher_.hash_leaf(entry.canonicalized_body());
      }
    catch (const std::exception &e)
      {
        logger_->error("Error computing leaf hash: {}", e.what());
        return "";
      }
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_checkpoint(const dev::sigstore::rekor::v1::Checkpoint &checkpoint,
                                                                       const std::string &expected_root_hash,
                                                                       int64_t expected_tree_size)
  {
    try
      {
        logger_->debug("Verifying checkpoint using CheckpointParser");

        // Use CheckpointParser to parse the checkpoint from protobuf
        CheckpointParser parser;
        auto parsed_result = parser.parse_from_protobuf(checkpoint);
        if (!parsed_result)
          {
            logger_->error("Failed to parse checkpoint from protobuf: {}", parsed_result.error().message());
            return parsed_result.error();
          }
        const auto &parsed_checkpoint = parsed_result.value();
        auto expected_root_hash_b64 = unfold::utils::Base64::encode(expected_root_hash);

        // Verify basic checkpoint fields
        if (parsed_checkpoint.origin.empty())
          {
            logger_->error("Checkpoint origin is empty");
            return SigstoreError::InvalidTransparencyLog;
          }
        if (static_cast<int64_t>(parsed_checkpoint.tree_size) != expected_tree_size)
          {
            logger_->error("Checkpoint tree size {} does not match expected tree size {}", parsed_checkpoint.tree_size, expected_tree_size);
            return SigstoreError::InvalidTransparencyLog;
          }
        if (parsed_checkpoint.root_hash != expected_root_hash_b64)
          {
            logger_->error("Checkpoint root hash {} does not match expected root hash {}", parsed_checkpoint.root_hash, expected_root_hash_b64);
            return SigstoreError::InvalidTransparencyLog;
          }

        // Verify checkpoint signatures
        if (parsed_checkpoint.signatures.empty())
          {
            logger_->error("No signatures found in checkpoint");
            return SigstoreError::InvalidTransparencyLog;
          }

        // Verify signatures using the checkpoint body
        for (const auto &sig: parsed_checkpoint.signatures)
          {
            if (sig.signer.starts_with("rekor.sigstore.dev"))
              {
                logger_->debug("Verifying checkpoint signature for signer: {}", sig.signer);
                auto valid = verify_rekor_log_entry_signature(parsed_checkpoint.body, sig.signature);
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

        logger_->debug("Checkpoint verification successful");
        return outcome::success();
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during checkpoint verification: {}", e.what());
        return SigstoreError::InvalidTransparencyLog;
      }
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_rekor_log_entry_signature(const std::string &log_entry, const std::string &signature_b64)
  {
    if (!rekor_public_key_)
      {
        logger_->error("Rekor public key is not loaded, cannot verify transparency log entry");
        return SigstoreError::InvalidTransparencyLog;
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
            return SigstoreError::InvalidTransparencyLog;
          }

        auto verify_result = rekor_public_key_->verify_signature(log_entry, signature_data);
        if (!verify_result)
          {
            return verify_result.error();
          }
        if (!verify_result.value())
          {
            logger_->error("Rekor log entry signature verification failed");
            return SigstoreError::InvalidTransparencyLog;
          }

        return outcome::success();
      }
    catch (const std::exception &e)
      {
        logger_->error("Exception during signature verification: {}", e.what());
        return SigstoreError::InvalidTransparencyLog;
      }
  }

  // =============================================================================
  // Signed Entry Timestamp
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_signed_entry_timestamp(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry)
  {
    try
      {
        logger_->debug("Verifying signed entry timestamp");
        if (!entry.has_inclusion_promise())
          {
            logger_->error("No inclusion promise to verify");
            return SigstoreError::InvalidTransparencyLog;
          }
        const dev::sigstore::rekor::v1::InclusionPromise &promise = entry.inclusion_promise();

        std::string signature_data = promise.signed_entry_timestamp();
        if (signature_data.empty())
          {
            logger_->error("Failed to decode signed entry timestamp");
            return SigstoreError::InvalidTransparencyLog;
          }

        if (entry.canonicalized_body().empty())
          {
            logger_->error("Cannot verify signed entry timestamp without body data");
            return SigstoreError::InvalidTransparencyLog;
          }

        std::string log_id;
        try
          {
            std::string key_id_binary = entry.log_id().key_id();

            std::stringstream hex_stream;
            hex_stream << std::hex << std::setfill('0');
            for (unsigned char byte: key_id_binary)
              {
                hex_stream << std::setw(2) << static_cast<unsigned int>(byte);
              }
            log_id = hex_stream.str();
          }
        catch (const std::exception &e)
          {
            logger_->error("Failed to decode base64 keyId: {}", e.what());
            return SigstoreError::InvalidTransparencyLog;
          }

        auto canonicalized_payload = fmt::format(R"({{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}})",
                                                 unfold::utils::Base64::encode(entry.canonicalized_body()),
                                                 entry.integrated_time(),
                                                 log_id,
                                                 entry.log_index());

        spdlog::debug("Canonicalized payload for signed entry timestamp verification: {}", canonicalized_payload);
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
        return SigstoreError::InvalidTransparencyLog;
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during signed entry timestamp verification: {}", e.what());
        return SigstoreError::InvalidTransparencyLog;
      }
  }

  // =============================================================================
  // Integrated Time
  // =============================================================================

  outcome::std_result<void> TransparencyLogVerifier::verify_integrated_time(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry,
                                                                            const Certificate &certificate)
  {
    try
      {

        int64_t integrated_time_seconds = entry.integrated_time();
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
            return SigstoreError::InvalidTransparencyLog;
          }

        auto current_time = std::chrono::system_clock::now();
        constexpr auto MAX_CLOCK_SKEW = std::chrono::seconds(300); // 5 minutes

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
        return SigstoreError::InvalidTransparencyLog;
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
        STACK_OF(ASN1_OBJECT) *eku = static_cast<STACK_OF(ASN1_OBJECT) *>(X509_get_ext_d2i(cert, NID_ext_key_usage, nullptr, nullptr));

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

  outcome::std_result<void> TransparencyLogVerifier::verify_bundle_consistency(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry,
                                                                               const dev::sigstore::bundle::v1::Bundle &bundle)
  {
    try
      {
        logger_->debug("Verifying bundle consistency with transparency log entry");

        if (entry.canonicalized_body().empty())
          {
            logger_->error("Cannot verify bundle consistency without body data");
            return SigstoreError::InvalidTransparencyLog;
          }
        if (!bundle.has_verification_material())
          {
            logger_->error("Bundle does not contain verification material");
            return SigstoreError::InvalidTransparencyLog;
          }
        if (!bundle.has_message_signature())
          {
            logger_->error("Bundle does not contain message signature");
            return SigstoreError::InvalidTransparencyLog;
          }

        CanonicalBodyParser body_parser;
        auto body_parse_result = body_parser.parse_from_json(entry.canonicalized_body());
        if (!body_parse_result)
          {
            logger_->error("Failed to parse canonicalized body: {}", body_parse_result.error().message());
            return body_parse_result.error();
          }
        const auto &body_entry = body_parse_result.value();

        return body_entry.spec.visit([bundle, body_entry, entry, this](auto &&spec) -> outcome::std_result<void> {
          using T = std::decay_t<decltype(spec)>;

          BundleHelper bundle_helper(bundle);
          auto bundle_certificate = bundle_helper.get_certificate();
          auto bundle_message_digest_opt = bundle_helper.get_message_digest();

          if (body_entry.kind != entry.kind_version().kind())
            {
              logger_->error("Bundle kind '{}' does not match canonicalized body kind '{}'", entry.kind_version().kind(), body_entry.kind);
              return SigstoreError::InvalidTransparencyLog;
            }
          if (body_entry.api_version != entry.kind_version().version())
            {
              logger_->error("Bundle API version '{}' does not match canonicalized body version '{}'", entry.kind_version().version(), body_entry.api_version);
              return SigstoreError::InvalidTransparencyLog;
            }

          if constexpr (std::is_same_v<T, HashedRekord>)
            {
              auto signature_valid = verify_signature_consistency(spec, bundle_helper);
              auto certificate_valid = verify_certificate_consistency(spec, *bundle_certificate);
              auto hash_valid = bundle_message_digest_opt.has_value() ? verify_hash_consistency(spec, bundle_helper) : outcome::success();
              if (signature_valid && certificate_valid && hash_valid)
                {
                  logger_->debug("Bundle consistency verification successful");
                  return outcome::success();
                }
              return SigstoreError::InvalidTransparencyLog;
            }
          else
            {
              logger_->error("Unsupported transparency log entry type for bundle consistency verification");
              return SigstoreError::InvalidTransparencyLog;
            }
        });
      }
    catch (const std::exception &e)
      {
        logger_->error("Error during bundle consistency verification: {}", e.what());
        return SigstoreError::SystemError;
      }
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_signature_consistency(const HashedRekord &rekord, const BundleHelper &bundle_helper)
  {
    if (rekord.signature != bundle_helper.get_signature())
      {
        logger_->error("Signature mismatch between bundle and transparency log");
        logger_->debug("Bundle signature: {}", bundle_helper.get_signature());
        logger_->debug("TLog signature:  {}", rekord.signature);
        return SigstoreError::InvalidTransparencyLog;
      }

    logger_->debug("Signature consistency verified");
    return outcome::success();
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_certificate_consistency(const HashedRekord &rekord, const Certificate &bundle_certificate)
  {
    std::string tlog_certificate_pem = rekord.public_key;

    auto tlog_cert_result = Certificate::from_pem(tlog_certificate_pem);
    if (!tlog_cert_result)
      {
        logger_->error("Failed to parse transparency log certificate from PEM");
        return SigstoreError::InvalidTransparencyLog;
      }

    if (bundle_certificate != tlog_cert_result.value())
      {
        logger_->error("Certificate mismatch between bundle and transparency log");
        return SigstoreError::InvalidTransparencyLog;
      }

    logger_->debug("Certificate consistency verified");
    return outcome::success();
  }

  outcome::std_result<void> TransparencyLogVerifier::verify_hash_consistency(const HashedRekord &rekord, const BundleHelper &bundle_helper)
  {
    std::string tlog_hash_hex = rekord.hash_value;

    std::string tlog_hash_binary;
    constexpr int HEX_BASE = 16;
    for (size_t i = 0; i < tlog_hash_hex.length(); i += 2)
      {
        std::string byte_str = tlog_hash_hex.substr(i, 2);
        auto byte = static_cast<unsigned char>(std::stoul(byte_str, nullptr, HEX_BASE));
        tlog_hash_binary.push_back(static_cast<char>(byte));
      }

    if (bundle_helper.get_message_digest().has_value() && bundle_helper.get_message_digest().value() != tlog_hash_binary)
      {
        logger_->error("Hash mismatch between bundle and transparency log");
        logger_->debug("Bundle hash: {}", unfold::utils::Base64::encode(bundle_helper.get_message_digest().value()));
        logger_->debug("TLog hash:   {}", unfold::utils::Base64::encode(tlog_hash_binary));
        return SigstoreError::InvalidTransparencyLog;
      }

    if (bundle_helper.get_algorithm().has_value() && bundle_helper.get_algorithm().value() != rekord.hash_algorithm)
      {
        logger_->error("Hash algorithm mismatch between bundle and transparency log");
        logger_->debug("Bundle hash algorithm: {}", bundle_helper.get_algorithm().value());
        logger_->debug("TLog hash algorithm:   {}", rekord.hash_algorithm);
        return SigstoreError::InvalidTransparencyLog;
      }
    logger_->debug("Hash consistency verified");
    return outcome::success();
  }

} // namespace unfold::sigstore
