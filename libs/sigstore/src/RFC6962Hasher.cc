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

#include "RFC6962Hasher.hh"

#include <array>
#include <openssl/evp.h>

namespace unfold::sigstore
{
  std::string RFC6962Hasher::hash_leaf(const std::string &data)
  {
    try
      {
        std::string prefixed_data;
        prefixed_data.reserve(1 + data.length());
        prefixed_data.push_back(static_cast<char>(LEAF_HASH_PREFIX));
        prefixed_data.append(data);
        std::string hash = sha256_hash(prefixed_data);
        return hash;
      }
    catch (const std::exception &e)
      {
        logger_->error("Error computing RFC 6962 leaf hash: {}", e.what());
        return "";
      }
  }

  std::string RFC6962Hasher::hash_children(const std::string &left_hash, const std::string &right_hash)
  {
    try
      {
        std::string prefixed_data;
        prefixed_data.reserve(1 + left_hash.length() + right_hash.length());
        prefixed_data.push_back(static_cast<char>(INTERNAL_HASH_PREFIX));
        prefixed_data.append(left_hash);
        prefixed_data.append(right_hash);
        std::string hash = sha256_hash(prefixed_data);
        return hash;
      }
    catch (const std::exception &e)
      {
        logger_->error("Error computing RFC 6962 internal node hash: {}", e.what());
        return "";
      }
  }

  std::string RFC6962Hasher::sha256_hash(const std::string &data)
  {
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash{};
    unsigned int hash_len = 0;

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
      {
        logger_->error("Failed to create EVP_MD_CTX for SHA256 hashing");
        return "";
      }

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
      {
        logger_->error("Failed to initialize SHA256 digest");
        return "";
      }

    if (EVP_DigestUpdate(ctx.get(), data.c_str(), data.size()) != 1)
      {
        logger_->error("Failed to update SHA256 digest");
        return "";
      }

    if (EVP_DigestFinal_ex(ctx.get(), hash.data(), &hash_len) != 1)
      {
        logger_->error("Failed to finalize SHA256 digest");
        return "";
      }

    return {hash.begin(), hash.begin() + hash_len};
  }

} // namespace unfold::sigstore
