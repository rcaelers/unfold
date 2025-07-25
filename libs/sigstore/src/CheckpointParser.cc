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

#include "CheckpointParser.hh"

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <algorithm>
#include <cctype>

#include "sigstore/SigstoreErrors.hh"

namespace unfold::sigstore
{
  outcome::std_result<ParsedCheckpoint> CheckpointParser::parse_from_protobuf(const dev::sigstore::rekor::v1::Checkpoint &protobuf_checkpoint)
  {
    if (protobuf_checkpoint.envelope().empty())
      {
        logger_->error("Protobuf checkpoint missing envelope field");
        return SigstoreError::InvalidBundle;
      }
    return parse_from_string(protobuf_checkpoint.envelope());
  }

  outcome::std_result<ParsedCheckpoint> CheckpointParser::parse_from_string(const std::string &checkpoint_data)
  {
    std::string normalized_text = boost::algorithm::replace_all_copy(checkpoint_data, "\r\n", "\n");
    const auto separator_pos = normalized_text.find("\n\n");
    if (separator_pos == std::string::npos)
      {
        logger_->error("Checkpoint format error: missing blank line between body and signatures");
        return SigstoreError::InvalidBundle;
      }

    auto body_text = std::string_view(normalized_text).substr(0, separator_pos);
    auto signature_text = std::string_view(normalized_text).substr(separator_pos + 2);

    ParsedCheckpoint checkpoint;
    if (!parse_checkpoint_body(body_text, checkpoint))
      {
        return SigstoreError::InvalidBundle;
      }
    if (!parse_checkpoint_signatures(signature_text, checkpoint))
      {
        return SigstoreError::InvalidBundle;
      }
    checkpoint.body = std::string(body_text) + "\n";
    return checkpoint;
  }

  bool CheckpointParser::parse_checkpoint_body(const std::string_view &body_text, ParsedCheckpoint &checkpoint)
  {
    std::vector<std::string_view> lines;
    boost::algorithm::split(lines, body_text, boost::is_any_of("\n"), boost::token_compress_off);
    if (!lines.empty() && lines.back().empty())
      {
        lines.pop_back();
      }
    if (lines.size() < 3)
      {
        logger_->error("Checkpoint body must have at least 3 lines");
        return false;
      }

    checkpoint.origin = std::string(lines[0]);
    std::string_view size_view = lines[1];
    if (!std::ranges::all_of(size_view, ::isdigit))
      {
        logger_->error("Tree size line is not decimal: {}", size_view);
        return false;
      }
    try
      {
        checkpoint.tree_size = std::stoull(std::string(size_view));
      }
    catch (const std::exception &e)
      {
        logger_->error("Failed to parse tree size: {}", e.what());
        return false;
      }
    checkpoint.root_hash = std::string(lines[2]);
    for (std::size_t i = 3; i < lines.size(); ++i)
      {
        checkpoint.extensions.emplace_back(lines[i]);
      }
    return true;
  }

  bool CheckpointParser::parse_checkpoint_signatures(const std::string_view &signature_text, ParsedCheckpoint &checkpoint)
  {
    std::vector<std::string_view> signature_lines;
    boost::algorithm::split(signature_lines, signature_text, boost::is_any_of("\n"), boost::token_compress_off);
    boost::algorithm::trim_right_if(signature_lines, [](const std::string_view &line) { return line.empty(); });
    if (signature_lines.empty())
      {
        logger_->error("Checkpoint has no signature lines");
        return false;
      }

    const std::string em_dash = "\u2014";
    for (auto line: signature_lines)
      {
        if (!line.starts_with(em_dash) && !line.starts_with("-"))
          {
            logger_->error("Signature line must start with dash: {}", line);
            return false;
          }
        line.remove_prefix(line.find_first_not_of("-\u2014 "));
        const auto space_pos = line.find(' ');
        if (space_pos == std::string_view::npos)
          {
            logger_->error("Signature line has no space after signer: {}", line);
            return false;
          }
        CheckpointSignature signature;
        signature.signer = std::string(line.substr(0, space_pos));
        signature.signature = std::string(line.substr(space_pos + 1));
        checkpoint.signatures.emplace_back(std::move(signature));
      }
    return true;
  }
} // namespace unfold::sigstore
