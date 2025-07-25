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

#ifndef CHECKPOINT_PARSER_HH
#define CHECKPOINT_PARSER_HH

#include <boost/outcome/std_result.hpp>
#include <memory>
#include <string>
#include <vector>

#include <spdlog/spdlog.h>
#include "utils/Logging.hh"
#include <sigstore_rekor.pb.h>

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  struct CheckpointSignature
  {
    std::string signer;
    std::string signature;
  };

  struct ParsedCheckpoint
  {
    std::string origin;
    std::uint64_t tree_size = 0;
    std::string root_hash;
    std::vector<std::string> extensions;
    std::vector<CheckpointSignature> signatures;
    std::string body;
  };

  class CheckpointParser
  {
  public:
    CheckpointParser() = default;

    outcome::std_result<ParsedCheckpoint> parse_from_string(const std::string &checkpoint_data);
    outcome::std_result<ParsedCheckpoint> parse_from_protobuf(const dev::sigstore::rekor::v1::Checkpoint &protobuf_checkpoint);

  private:
    bool parse_checkpoint_body(const std::string_view &body_text, ParsedCheckpoint &checkpoint);
    bool parse_checkpoint_signatures(const std::string_view &signature_text, ParsedCheckpoint &checkpoint);

    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:checkpoint_parser")};
  };

} // namespace unfold::sigstore

#endif // CHECKPOINT_PARSER_HH
