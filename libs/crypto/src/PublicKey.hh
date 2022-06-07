// Copyright (C) 2022 Rob Caelers <rob.caelers@gmail.com>
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

#ifndef PUBLIC_KEYS_HH
#define PUBLIC_KEYS_HH

#include <string>

#include <openssl/pem.h>

#include "utils/Logging.hh"

class PublicKey
{
public:
  explicit PublicKey(std::string public_key);
  ~PublicKey();

  PublicKey(const PublicKey &) = delete;
  PublicKey &operator=(const PublicKey &) = delete;
  PublicKey(PublicKey &&) = delete;
  PublicKey &operator=(PublicKey &&) = delete;

  EVP_PKEY *get() const;

private:
  void load();
  void load_pem();
  void load_der();
  void load_base64_der();

private:
  std::string public_key;
  EVP_PKEY *pkey{nullptr};
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:signatures")};
};

#endif // PUBLIC_KEYS_HH
