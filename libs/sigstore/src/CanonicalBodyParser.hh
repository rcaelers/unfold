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

#ifndef CANONICAL_BODY_PARSER_HH
#define CANONICAL_BODY_PARSER_HH

#include <boost/outcome/std_result.hpp>
#include <boost/json/object.hpp>
#include <memory>
#include <string>

#include <spdlog/spdlog.h>
#include "utils/Logging.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  struct HashedRekord
  {
    std::string hash_algorithm;
    std::string hash_value;
    std::string signature;
    std::string public_key;
  };

  struct LogEntry
  {
    std::string kind;
    std::string api_version;
    std::variant<HashedRekord> spec;
  };

  class CanonicalBodyParser
  {
  public:
    CanonicalBodyParser() = default;

    outcome::std_result<LogEntry> parse_from_base64_json(const std::string &base64_encoded_body);
    outcome::std_result<LogEntry> parse_from_json(const std::string &json_body);

  private:
    outcome::std_result<HashedRekord> parse_hashed_rekord_spec(const boost::json::object &spec_obj);

  private:
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:canonical_body_parser")};
  };

} // namespace unfold::sigstore

#endif // CANONICAL_BODY_PARSER_HH
