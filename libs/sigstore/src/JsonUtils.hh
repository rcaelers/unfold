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

#ifndef SIGSTORE_JSON_UTILS_HH
#define SIGSTORE_JSON_UTILS_HH

#include <string>
#include <memory>
#include <boost/json.hpp>
#include <spdlog/spdlog.h>

#include "utils/Logging.hh"

namespace unfold::sigstore
{
  class JsonUtils
  {
  public:
    JsonUtils() = default;

    std::string extract_string(const boost::json::value &json_val, const std::string &key);
    boost::json::value extract_object(const boost::json::value &json_val, const std::string &key);
    boost::json::value extract_array_element(const boost::json::value &json_val, const std::string &key, size_t index = 0);

  private:
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:json")};
    static constexpr size_t LOG_PREVIEW_MAX_LENGTH = 100;
  };

} // namespace unfold::sigstore

#endif // SIGSTORE_JSON_UTILS_HH
