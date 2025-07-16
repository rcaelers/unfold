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

#ifndef TRANSPARENCY_LOG_ENTRY_HH
#define TRANSPARENCY_LOG_ENTRY_HH

#include <boost/json.hpp>
#include <boost/outcome/std_result.hpp>
#include <optional>
#include <vector>
#include <string>
#include <memory>

#include <spdlog/spdlog.h>
#include "utils/Logging.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  struct KindVersion
  {
    std::string kind;
    std::string version;
  };

  struct InclusionPromise
  {
    std::string signed_entry_timestamp;
  };

  struct Checkpoint
  {
    std::string envelope;
  };

  struct InclusionProof
  {
    int64_t log_index;
    std::string root_hash;
    int64_t tree_size;
    std::vector<std::string> hashes;
    std::optional<Checkpoint> checkpoint;
  };

  struct TransparencyLogEntry
  {
    int64_t log_index;
    std::optional<std::string> log_id;
    std::optional<KindVersion> kind_version;
    std::optional<int64_t> integrated_time;
    std::optional<InclusionPromise> inclusion_promise;
    std::optional<InclusionProof> inclusion_proof;
    std::optional<std::string> body;
  };

  class TransparencyLogEntryParser
  {
  public:
    TransparencyLogEntryParser() = default;

    outcome::std_result<TransparencyLogEntry> parse(const boost::json::value &json_val);
    outcome::std_result<TransparencyLogEntry> parse_api_response(const boost::json::value &json_val);

  private:
    outcome::std_result<int64_t> parse_log_index(const boost::json::object &obj);
    void parse_optional_fields(const boost::json::object &obj, TransparencyLogEntry &entry);
    void parse_api_fields(const boost::json::object &obj, TransparencyLogEntry &entry);
    std::optional<int64_t> parse_integrated_time(const boost::json::value &json_val);
    std::optional<int64_t> parse_int64_value(const boost::json::value &json_val);
    outcome::std_result<std::string> parse_log_id(const boost::json::value &json_val);
    outcome::std_result<KindVersion> parse_kind_version(const boost::json::value &json_val);
    outcome::std_result<InclusionPromise> parse_inclusion_promise(const boost::json::value &json_val);
    outcome::std_result<InclusionProof> parse_inclusion_proof(const boost::json::value &json_val);
    outcome::std_result<Checkpoint> parse_checkpoint(const boost::json::value &json_val);

    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:transparency_log_entry")};
  };

} // namespace unfold::sigstore

#endif // TRANSPARENCY_LOG_ENTRY_HH
