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
#include "crypto/SignatureVerifierErrors.hh"

#include <cstddef>
#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include <openssl/err.h>

using namespace unfold::crypto;

ECDSASignatureAlgorithm::ECDSASignatureAlgorithm(const std::string &public_key)
  : public_key(public_key)
{
}

outcome::std_result<void>
ECDSASignatureAlgorithm::verify(std::string_view data, const std::string &signature)
{
  EVP_PKEY *pkey = public_key.get();

  if (pkey == nullptr)
    {
      logger->error("failed load public key ({})", ERR_error_string(ERR_get_error(), nullptr));
      return SignatureVerifierErrc::InvalidPublicKey;
    }

  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
  if (md_ctx == nullptr)
    {
      logger->error("failed to check signature ({})", ERR_error_string(ERR_get_error(), nullptr));
      return SignatureVerifierErrc::InternalFailure;
    }

  auto ret = EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey);
  if (ret == 0)
    {
      logger->error("failed to check signature ({})", ERR_error_string(ERR_get_error(), nullptr));
      EVP_MD_CTX_free(md_ctx);
      return SignatureVerifierErrc::InternalFailure;
    }

  ret = EVP_DigestVerify(md_ctx,
                         reinterpret_cast<const unsigned char *>(signature.data()),
                         signature.size(),
                         reinterpret_cast<const unsigned char *>(data.data()),
                         data.size());

  auto rc = SignatureVerifierErrc::Success;

  if (ret == 0)
    {
      rc = SignatureVerifierErrc::Mismatch;
    }
  else if (ret != 1)
    {
      logger->error("failed to check signature: {}", ERR_error_string(ERR_get_error(), nullptr));
      rc = SignatureVerifierErrc::InternalFailure;
    }

  EVP_MD_CTX_free(md_ctx);
  return rc;
}
