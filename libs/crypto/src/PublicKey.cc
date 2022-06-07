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

#include "utils/Base64.hh"
#include "PublicKey.hh"

#include <openssl/evp.h>

PublicKey::PublicKey(std::string public_key)
  : public_key(std::move(public_key))
{
  load();
}

PublicKey::~PublicKey()
{
  if (pkey != nullptr)
    {
      EVP_PKEY_free(pkey);
    }
}
void
PublicKey::load_pem()
{
  BIO *bio = BIO_new_mem_buf(reinterpret_cast<const unsigned char *>(public_key.data()), static_cast<int>(public_key.size()));
  if (bio != nullptr)
    {
      PEM_read_bio_PUBKEY(bio, &pkey, nullptr, nullptr);
      BIO_free_all(bio);
    }
}

void
PublicKey::load_der()
{
  BIO *bio = BIO_new_mem_buf(reinterpret_cast<const unsigned char *>(public_key.data()), static_cast<int>(public_key.size()));
  if (bio != nullptr)
    {
      d2i_PUBKEY_bio(bio, &pkey);
      BIO_free_all(bio);
    }
}

void
PublicKey::load_base64_der()
{
  try
    {
      std::string p = unfold::utils::Base64::decode(public_key);
      BIO *bio = BIO_new_mem_buf(reinterpret_cast<const unsigned char *>(p.data()), static_cast<int>(p.size()));
      if (bio != nullptr)
        {
          d2i_PUBKEY_bio(bio, &pkey);
          BIO_free_all(bio);
        }
    }
  catch (std::exception &e)
    {
      logger->info("failed to load base64 decode pem certificate ({})", e.what());
    }
}

void
PublicKey::load()
{
  load_pem();
  if (pkey == nullptr)
    {
      load_der();
    }
  if (pkey == nullptr)
    {
      load_base64_der();
    }
}

EVP_PKEY *
PublicKey::get() const
{
  return pkey;
}
