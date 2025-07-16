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

#ifndef PUBLICKEY_HH
#define PUBLICKEY_HH

#include <memory>
#include <string>
#include <vector>
#include <boost/outcome/std_result.hpp>
#include <spdlog/spdlog.h>
#include <openssl/evp.h>

#include "utils/Logging.hh"
#include "CryptographicAlgorithms.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  class PublicKey
  {
  private:
    struct EVPKeyDeleter
    {
      void operator()(EVP_PKEY *key) const
      {
        if (key != nullptr)
          {
            EVP_PKEY_free(key);
          }
      }
    };

  public:
    explicit PublicKey(std::unique_ptr<EVP_PKEY, EVPKeyDeleter> evp_key);
    PublicKey() = delete;
    PublicKey(PublicKey &&other) noexcept = default;
    PublicKey &operator=(PublicKey &&other) noexcept = default;
    PublicKey(const PublicKey &) = delete;
    PublicKey &operator=(const PublicKey &) = delete;
    ~PublicKey() = default;

    static outcome::std_result<PublicKey> from_pem(const std::string &key_pem);
    static outcome::std_result<PublicKey> from_der(const std::vector<uint8_t> &key_der);
    static outcome::std_result<PublicKey> from_der(const std::string &key_der);
    static outcome::std_result<PublicKey> from_certificate(const std::string &cert_pem);
    static outcome::std_result<PublicKey> from_evp_key(EVP_PKEY *evp_key);

    EVP_PKEY *get() const;
    KeyAlgorithm get_algorithm() const;
    int get_key_size_bits() const;
    std::string get_algorithm_name() const;

    outcome::std_result<bool> verify_signature(const std::vector<uint8_t> &data,
                                               const std::vector<uint8_t> &signature,
                                               DigestAlgorithm digest_algorithm = DigestAlgorithm::SHA256) const;

    outcome::std_result<bool> verify_signature(const std::string &data,
                                               const std::string &signature,
                                               DigestAlgorithm digest_algorithm = DigestAlgorithm::SHA256) const;

  private:
    std::unique_ptr<EVP_PKEY, EVPKeyDeleter> evp_key_{nullptr};
    std::shared_ptr<spdlog::logger> logger_{unfold::utils::Logging::create("unfold:sigstore:publickey")};
  };

} // namespace unfold::sigstore

#endif // PUBLICKEY_HH
