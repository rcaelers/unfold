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

#include "TransparencyLogEntry.hh"

#include <algorithm>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string.hpp>

#include "sigstore/SigstoreErrors.hh"
#include "utils/Base64.hh"

#include <string>
#include <iomanip>
#include <sstream>
#include <limits>

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  outcome::std_result<TransparencyLogEntry> TransparencyLogEntryParser::parse(const boost::json::value &json_val)
  {
    if (!json_val.is_object())
      {
        logger_->error("Invalid tlog entry JSON in Sigstore Bundle");
        return SigstoreError::InvalidBundle;
      }

    const auto &obj = json_val.as_object();
    TransparencyLogEntry entry{};

    // Parse required logIndex
    auto log_index_result = parse_log_index(obj);
    if (!log_index_result)
      {
        logger_->error("Failed to parse logIndex: {}", log_index_result.error().message());
        return log_index_result.error();
      }
    entry.log_index = log_index_result.value();

    // Parse optional fields
    parse_optional_fields(obj, entry);

    return entry;
  }

  outcome::std_result<int64_t> TransparencyLogEntryParser::parse_log_index(const boost::json::object &obj)
  {
    if (const auto *it = obj.if_contains("logIndex"))
      {
        auto parsed_value = parse_int64_value(*it);
        if (parsed_value)
          {
            return parsed_value.value();
          }
        return SigstoreError::InvalidBundle;
      }
    return SigstoreError::InvalidBundle;
  }

  void TransparencyLogEntryParser::parse_optional_fields(const boost::json::object &obj, TransparencyLogEntry &entry)
  {
    // Parse optional logId
    if (const auto *it = obj.if_contains("logId"))
      {
        auto log_id_result = parse_log_id(*it);
        if (log_id_result)
          {
            entry.log_id = log_id_result.value();
          }
        else
          {
            logger_->warn("Failed to parse logId: {}", log_id_result.error().message());
          }
      }

    // Parse optional kindVersion
    if (const auto *it = obj.if_contains("kindVersion"))
      {
        auto kind_version_result = parse_kind_version(*it);
        if (kind_version_result)
          {
            entry.kind_version = kind_version_result.value();
          }
        else
          {
            logger_->warn("Failed to parse kindVersion: {}", kind_version_result.error().message());
          }
      }

    // Parse optional integratedTime
    if (const auto *it = obj.if_contains("integratedTime"))
      {
        entry.integrated_time = parse_integrated_time(*it);
        logger_->debug("Parsed integratedTime: {}",
                       entry.integrated_time.has_value() ? std::to_string(entry.integrated_time.value()) : "none");
      }

    // Parse optional inclusionPromise
    if (const auto *it = obj.if_contains("inclusionPromise"))
      {
        auto inclusion_promise_result = parse_inclusion_promise(*it);
        if (inclusion_promise_result)
          {
            entry.inclusion_promise = inclusion_promise_result.value();
          }
        else
          {
            logger_->warn("Failed to parse inclusionPromise: {}", inclusion_promise_result.error().message());
          }
      }

    // Parse optional inclusionProof
    if (const auto *it = obj.if_contains("inclusionProof"))
      {
        auto inclusion_proof_result = parse_inclusion_proof(*it);
        if (inclusion_proof_result)
          {
            entry.inclusion_proof = inclusion_proof_result.value();
          }
        else
          {
            logger_->warn("Failed to parse inclusionProof: {}", inclusion_proof_result.error().message());
          }
      }

    // Parse optional canonicalizedBody (bundle format)
    if (const auto *it = obj.if_contains("canonicalizedBody"))
      {
        if (it->is_string())
          {
            entry.body = std::string(it->as_string());
          }
      }
  }

  void TransparencyLogEntryParser::parse_api_fields(const boost::json::object &obj, TransparencyLogEntry &entry)
  {
    // Parse body field (base64 encoded content from API) - only if not already set by canonicalizedBody
    if (const auto *it = obj.if_contains("body"))
      {
        if (it->is_string() && !entry.body.has_value())
          {
            entry.body = std::string(it->as_string());
          }
      }

    // Parse logID field (string format from API) and store in log_id.id
    if (const auto *it = obj.if_contains("logID"))
      {
        if (it->is_string())
          {
            entry.log_id = std::string(it->as_string());
          }
      }

    // Parse verification section and map to existing bundle fields
    if (const auto *it = obj.if_contains("verification"))
      {
        if (it->is_object())
          {
            const auto &verification_obj = it->as_object();

            // Map verification.inclusionProof to entry.inclusion_proof
            if (const auto *proof_it = verification_obj.if_contains("inclusionProof"))
              {
                auto inclusion_proof_result = parse_inclusion_proof(*proof_it);
                if (inclusion_proof_result)
                  {
                    entry.inclusion_proof = inclusion_proof_result.value();
                  }
                else
                  {
                    logger_->warn("Failed to parse inclusionProof from verification: {}",
                                  inclusion_proof_result.error().message());
                  }
              }

            // Map verification.signedEntryTimestamp to entry.inclusion_promise
            if (const auto *timestamp_it = verification_obj.if_contains("signedEntryTimestamp"))
              {
                if (timestamp_it->is_string())
                  {
                    InclusionPromise promise;
                    promise.signed_entry_timestamp = std::string(timestamp_it->as_string());
                    entry.inclusion_promise = promise;
                  }
              }
          }
      }
  }

  outcome::std_result<TransparencyLogEntry> TransparencyLogEntryParser::parse_api_response(const boost::json::value &json_val)
  {
    if (!json_val.is_object())
      {
        logger_->error("Invalid API response JSON - expected object");
        return SigstoreError::InvalidBundle;
      }

    const auto &root_obj = json_val.as_object();

    // Real API responses have entry UUIDs as keys, extract the first entry
    if (root_obj.empty())
      {
        logger_->error("Empty API response");
        return SigstoreError::InvalidBundle;
      }

    // Get the first (and typically only) entry
    const auto &entry_pair = *root_obj.begin();
    const auto &entry_data = entry_pair.value();

    if (!entry_data.is_object())
      {
        logger_->error("Invalid entry data in API response");
        return SigstoreError::InvalidBundle;
      }

    const auto &obj = entry_data.as_object();
    TransparencyLogEntry entry{};

    // Parse required logIndex (could be "logIndex" in bundle format)
    auto log_index_result = parse_log_index(obj);
    if (!log_index_result)
      {
        logger_->error("Failed to parse logIndex: {}", log_index_result.error().message());
        return log_index_result.error();
      }
    entry.log_index = log_index_result.value();

    // Parse both bundle-style and API-style fields
    parse_optional_fields(obj, entry);
    parse_api_fields(obj, entry);

    return entry;
  }

  std::optional<int64_t> TransparencyLogEntryParser::parse_integrated_time(const boost::json::value &json_val)
  {
    return parse_int64_value(json_val);
  }

  outcome::std_result<std::string> TransparencyLogEntryParser::parse_log_id(const boost::json::value &json_val)
  {
    if (!json_val.is_object())
      {
        return SigstoreError::InvalidBundle;
      }

    const auto &obj = json_val.as_object();
    std::string log_id;

    if (const auto *it = obj.if_contains("keyId"); it != nullptr && it->is_string())
      {
        // Bundle format uses base64-encoded keyId, convert to hex for consistency
        std::string key_id_b64 = std::string(it->as_string());
        try
          {
            std::string key_id_binary = unfold::utils::Base64::decode(key_id_b64);

            // Convert binary to hex string
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
            logger_->warn("Failed to decode base64 keyId: {}", e.what());
            // Fall back to storing the base64 string directly
            log_id = key_id_b64;
          }
      }

    return log_id;
  }

  outcome::std_result<KindVersion> TransparencyLogEntryParser::parse_kind_version(const boost::json::value &json_val)
  {
    if (!json_val.is_object())
      {
        return SigstoreError::InvalidBundle;
      }

    const auto &obj = json_val.as_object();
    KindVersion kind_version{};

    if (const auto *it = obj.if_contains("kind"); it != nullptr && it->is_string())
      {
        kind_version.kind = std::string(it->as_string());
      }

    if (const auto *it = obj.if_contains("version"); it != nullptr && it->is_string())
      {
        kind_version.version = std::string(it->as_string());
      }

    return kind_version;
  }

  outcome::std_result<InclusionPromise> TransparencyLogEntryParser::parse_inclusion_promise(const boost::json::value &json_val)
  {
    if (!json_val.is_object())
      {
        return SigstoreError::InvalidBundle;
      }

    const auto &obj = json_val.as_object();
    InclusionPromise inclusion_promise{};

    if (const auto *it = obj.if_contains("signedEntryTimestamp"); it != nullptr && it->is_string())
      {
        inclusion_promise.signed_entry_timestamp = std::string(it->as_string());
      }

    return inclusion_promise;
  }

  outcome::std_result<InclusionProof> TransparencyLogEntryParser::parse_inclusion_proof(const boost::json::value &json_val)
  {
    if (!json_val.is_object())
      {
        return SigstoreError::InvalidBundle;
      }

    const auto &obj = json_val.as_object();
    InclusionProof inclusion_proof{};

    // Parse logIndex
    if (const auto *it = obj.if_contains("logIndex"))
      {
        auto log_index_opt = parse_int64_value(*it);
        if (!log_index_opt)
          {
            return SigstoreError::InvalidBundle;
          }
        inclusion_proof.log_index = *log_index_opt;
      }

    // Parse rootHash
    if (const auto *it = obj.if_contains("rootHash"); it != nullptr && it->is_string())
      {
        inclusion_proof.root_hash = std::string(it->as_string());
      }

    // Parse treeSize
    if (const auto *it = obj.if_contains("treeSize"))
      {
        auto tree_size_opt = parse_int64_value(*it);
        if (tree_size_opt)
          {
            inclusion_proof.tree_size = *tree_size_opt;
          }
      }

    // Parse hashes array
    if (const auto *it = obj.if_contains("hashes"); it != nullptr && it->is_array())
      {
        const auto &hashes_array = it->as_array();
        inclusion_proof.hashes.reserve(hashes_array.size());

        for (const auto &hash_val: hashes_array)
          {
            if (hash_val.is_string())
              {
                inclusion_proof.hashes.emplace_back(hash_val.as_string());
              }
          }
      }

    // Parse optional checkpoint
    if (const auto *it = obj.if_contains("checkpoint"); it != nullptr && it->is_object())
      {
        const auto &checkpoint_obj = it->as_object();

        if (const auto *it = checkpoint_obj.if_contains("envelope"); it != nullptr && it->is_string())
          {
            auto checkpoint_result = parse_checkpoint(std::string(it->as_string()));
            if (checkpoint_result)
              {
                inclusion_proof.checkpoint = checkpoint_result.value();
              }
            else
              {
                logger_->warn("Failed to parse checkpoint: {}", checkpoint_result.error().message());
              }
          }
      }

    return inclusion_proof;
  }

  outcome::std_result<Checkpoint> TransparencyLogEntryParser::parse_checkpoint(const std::string &checkpoint)
  {
    std::string text = boost::algorithm::replace_all_copy(std::string(checkpoint), "\r\n", "\n");

    const auto sep = text.find("\n\n");
    if (sep == std::string::npos)
      {
        logger_->error("Checkpoint format error: missing blank line between body and signatures");
        return SigstoreError::InvalidBundle;
      }

    auto body = std::string_view(text).substr(0, sep);
    auto sig_block = std::string_view(text).substr(sep + 2);

    logger_->debug("Parsing checkpoint with body:\n{}", body);
    logger_->debug("Parsing checkpoint signatures:\n{}", sig_block);

    /* ---- body ---- */
    std::vector<std::string_view> lines;
    boost::algorithm::split(lines, body, boost::is_any_of("\n"), boost::token_compress_off);
    if (!lines.empty() && lines.back().empty())
      {
        lines.pop_back();
      }

    if (lines.size() < 3)
      {
        logger_->error("Checkpoint body must have at least 3 lines");
        return SigstoreError::InvalidBundle;
      }

    Checkpoint ck;
    ck.body = std::string(body) + "\n";
    ck.origin = std::string(lines[0]);

    std::string_view size_sv = lines[1];
    if (!std::ranges::all_of(size_sv, ::isdigit))
      {
        logger_->error("Tree size line is not decimal: {}", size_sv);
        return SigstoreError::InvalidBundle;
      }
    ck.tree_size = std::stoull(std::string(size_sv));
    ck.root_hash = std::string(lines[2]);

    for (std::size_t i = 3; i < lines.size(); ++i)
      {
        ck.extensions.emplace_back(lines[i]);
      }

    /* ---- signatures ---- */
    std::vector<std::string_view> sig_lines;
    boost::algorithm::split(sig_lines, sig_block, boost::is_any_of("\n"), boost::token_compress_off);
    boost::algorithm::trim_right_if(sig_lines, [](const std::string_view &line) { return line.empty(); });

    if (sig_lines.empty())
      {
        logger_->error("Checkpoint has no signature lines");
        return SigstoreError::InvalidBundle;
      }

    const std::string em_dash = "\u2014"; // UTF-8 em dash

    for (auto ln: sig_lines)
      {
        if (!ln.starts_with(em_dash) && !ln.starts_with("-"))
          {
            logger_->error("Signature line must start with em dash or hyphen: {}", ln);
            return SigstoreError::InvalidBundle;
          }

        ln.remove_prefix(ln.find_first_not_of("-\u2014 "));
        const auto sp = ln.find(' ');
        if (sp == std::string_view::npos)
          {
            logger_->error("Signature line has no space after signer: {}", ln);
            return SigstoreError::InvalidBundle;
          }

        Signature sig;
        sig.signer = std::string(ln.substr(0, sp));
        sig.signature = std::string(ln.substr(sp + 1));
        ck.signatures.emplace_back(std::move(sig));
      }

    return ck;
  }

  std::optional<int64_t> TransparencyLogEntryParser::parse_int64_value(const boost::json::value &json_val)
  {
    if (json_val.is_string())
      {
        try
          {
            return std::stoll(std::string(json_val.as_string()));
          }
        catch (const std::exception &)
          {
            return std::nullopt;
          }
      }
    else if (json_val.is_int64())
      {
        return json_val.as_int64();
      }
    else if (json_val.is_uint64())
      {
        uint64_t value = json_val.as_uint64();
        // Check if the uint64 value fits in int64 range
        if (value <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
          {
            return static_cast<int64_t>(value);
          }
      }
    return std::nullopt;
  }

} // namespace unfold::sigstore
