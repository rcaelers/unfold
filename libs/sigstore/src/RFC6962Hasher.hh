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

#pragma once

#include <string>
#include <memory>
#include <spdlog/logger.h>

#include "utils/Logging.hh"

namespace unfold::sigstore
{
  class RFC6962Hasher
  {
  public:
    RFC6962Hasher() = default;
    ~RFC6962Hasher() = default;

    RFC6962Hasher(const RFC6962Hasher &) = delete;
    RFC6962Hasher &operator=(const RFC6962Hasher &) = delete;
    RFC6962Hasher(RFC6962Hasher &&) = default;
    RFC6962Hasher &operator=(RFC6962Hasher &&) = default;

    std::string hash_leaf(const std::string &data);
    std::string hash_children(const std::string &left_hash, const std::string &right_hash);

  private:
    std::string sha256_hash(const std::string &data);

  private:
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:rfc6962hasher")};

    static constexpr unsigned char LEAF_HASH_PREFIX = 0x00;
    static constexpr unsigned char INTERNAL_HASH_PREFIX = 0x01;
  };

} // namespace unfold::sigstore
