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

#include "ECDSASignatureAlgorithm.hh"
#include "PublicKey.hh"
#include "crypto/SignatureVerifierErrors.hh"

#include <cstddef>
#include <memory>
#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include <openssl/err.h>

using namespace unfold::crypto;

namespace
{
  constexpr size_t ED25519_SIGNATURE_SIZE = 64;
}

outcome::std_result<void>
ECDSASignatureAlgorithm::set_key(const std::string &key)
{
  public_key = std::make_unique<PublicKey>(key);

  EVP_PKEY *pkey = public_key->get();

  if (pkey == nullptr)
    {
      logger->error("failed load public key ({})", ERR_error_string(ERR_get_error(), nullptr));
      return SignatureVerifierErrc::InvalidPublicKey;
    }
  return outcome::success();
}

outcome::std_result<void>
ECDSASignatureAlgorithm::verify(std::string_view data, const std::string &signature)
{
  EVP_PKEY *pkey = public_key->get();

  if (pkey == nullptr)
    {
      logger->error("failed load public key ({})", ERR_error_string(ERR_get_error(), nullptr));
      ERR_clear_error();
      return SignatureVerifierErrc::InvalidPublicKey;
    }

  if (EVP_PKEY_base_id(pkey) != EVP_PKEY_ED25519)
    {
      logger->error("invalid public key type: expected ED25519, got {}", EVP_PKEY_base_id(pkey));
      return SignatureVerifierErrc::InvalidPublicKey;
    }

  if (data.size() > INT_MAX)
    {
      logger->error("data exceeds maximum data size = {}", data.size());
      return SignatureVerifierErrc::InternalFailure;
    }

  if (signature.size() != ED25519_SIGNATURE_SIZE)
    {
      logger->error("signature has invalid size = {}", signature.size());
      return SignatureVerifierErrc::InternalFailure;
    }

  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  if (md_ctx == nullptr)
    {
      logger->error("failed to check signature ({})", ERR_error_string(ERR_get_error(), nullptr));
      ERR_clear_error();
      return SignatureVerifierErrc::InternalFailure;
    }

  auto ret = EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey);
  if (ret == 0)
    {
      logger->error("failed to check signature ({})", ERR_error_string(ERR_get_error(), nullptr));
      EVP_MD_CTX_free(md_ctx);
      ERR_clear_error();
      return SignatureVerifierErrc::InternalFailure;
    }

  ret = EVP_DigestVerify(
    md_ctx,
    reinterpret_cast<const unsigned char *>(signature.data()), // NOLINT:cppcoreguidelines-pro-type-reinterpret-cast
    signature.size(),
    reinterpret_cast<const unsigned char *>(data.data()), // NOLINT:cppcoreguidelines-pro-type-reinterpret-cast
    data.size());

  outcome::std_result<void> rc = outcome::success();

  if (ret == 0)
    {
      rc = outcome::failure(SignatureVerifierErrc::Mismatch);
    }
  else if (ret != 1)
    {
      logger->error("failed to check signature: {}", ERR_error_string(ERR_get_error(), nullptr));
      ERR_clear_error();
      rc = outcome::failure(SignatureVerifierErrc::InternalFailure);
    }

  EVP_MD_CTX_free(md_ctx);
  return rc;
}
