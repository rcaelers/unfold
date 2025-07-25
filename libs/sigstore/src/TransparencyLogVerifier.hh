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

#ifndef TRANSPARENCY_LOG_VERIFIER_HH
#define TRANSPARENCY_LOG_VERIFIER_HH

#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include <openssl/evp.h>
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <boost/outcome/std_result.hpp>
#include <spdlog/spdlog.h>

#include "BundleHelper.hh"
#include "CanonicalBodyParser.hh"
#include "RFC6962Hasher.hh"
#include "utils/Logging.hh"

#include "sigstore_bundle.pb.h"
#include "sigstore_rekor.pb.h"

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  class Certificate;
  class PublicKey;
  class MerkleTreeValidator;

  class TransparencyLogVerifier
  {
  public:
    struct VerificationConfig
    {
      static constexpr int DEFAULT_CLOCK_SKEW_SECONDS = 300; // 5 minutes
      static constexpr int SECONDS_PER_HOUR = 3600;
      static constexpr int HOURS_PER_DAY = 24;
      static constexpr int DAYS_PER_YEAR = 365;
      static constexpr int DEFAULT_MAX_ENTRY_AGE_SECONDS = DAYS_PER_YEAR * HOURS_PER_DAY * SECONDS_PER_HOUR;

      std::vector<std::string> trusted_oidc_issuers;
      std::chrono::seconds max_clock_skew;
      std::chrono::seconds max_entry_age;
      bool strict_issuer_validation{false}; // Warn vs fail for untrusted issuers

      VerificationConfig()
        : trusted_oidc_issuers{"https://github.com/login/oauth",
                               "https://gitlab.com",
                               "https://accounts.google.com",
                               "https://oauth2.sigstore.dev/auth"}
        , max_clock_skew{DEFAULT_CLOCK_SKEW_SECONDS}
        , max_entry_age{DEFAULT_MAX_ENTRY_AGE_SECONDS}
      {
      }
    };

    explicit TransparencyLogVerifier(VerificationConfig config = VerificationConfig{});
    ~TransparencyLogVerifier();

    TransparencyLogVerifier(const TransparencyLogVerifier &) = delete;
    TransparencyLogVerifier &operator=(const TransparencyLogVerifier &) = delete;
    TransparencyLogVerifier(TransparencyLogVerifier &&) noexcept = default;
    TransparencyLogVerifier &operator=(TransparencyLogVerifier &&) noexcept = default;

    outcome::std_result<void> verify_transparency_log(dev::sigstore::rekor::v1::TransparencyLogEntry entry, const Certificate &certificate);
    outcome::std_result<void> verify_bundle_consistency(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry,
                                                        const dev::sigstore::bundle::v1::Bundle &bundle);

  private:
    outcome::std_result<void> verify_inclusion_proof(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry);
    outcome::std_result<void> verify_checkpoint(const dev::sigstore::rekor::v1::Checkpoint &checkpoint,
                                                const std::string &expected_root_hash,
                                                int64_t expected_tree_size);
    outcome::std_result<void> verify_signed_entry_timestamp(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry);
    outcome::std_result<void> verify_integrated_time(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry, const Certificate &certificate);
    outcome::std_result<void> verify_certificate_extensions(const Certificate &certificate,
                                                            const std::string &expected_email = "",
                                                            const std::string &expected_issuer = "");
    outcome::std_result<void> verify_certificate_key_usage(const Certificate &certificate);
    outcome::std_result<void> verify_rekor_log_entry_signature(const std::string &log_entry, const std::string &signature_b64);

    outcome::std_result<void> verify_signature_consistency(const HashedRekord &rekord, const BundleHelper &bundle_helper);
    outcome::std_result<void> verify_certificate_consistency(const HashedRekord &rekord, const Certificate &bundle_certificate);
    outcome::std_result<void> verify_hash_consistency(const HashedRekord &rekord, const BundleHelper &bundle_helper);

    std::string compute_leaf_hash(const dev::sigstore::rekor::v1::TransparencyLogEntry &entry);
    outcome::std_result<void> load_embedded_certificates();

  private:
    VerificationConfig config_;
    RFC6962Hasher hasher_;
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:transparency_log_verifier")};
    std::unique_ptr<PublicKey> rekor_public_key_;
    std::unique_ptr<MerkleTreeValidator> merkle_validator_;
  };

} // namespace unfold::sigstore

#endif // TRANSPARENCY_LOG_VERIFIER_HH
