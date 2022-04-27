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

#include "crypto/SignatureVerifierErrors.hh"

using namespace unfold::crypto;

namespace
{
  struct SignatureVerifierErrorCategory : std::error_category
  {
    const char *name() const noexcept override
    {
      return "signatures";
    }
    std::string message(int ev) const override;
  };

  std::string SignatureVerifierErrorCategory::message(int ev) const
  {
    switch (static_cast<SignatureVerifierErrc>(ev))
      {
      case SignatureVerifierErrc::Success:
        return "signature correct";
      case SignatureVerifierErrc::NotFound:
        return "file not found";
      case SignatureVerifierErrc::InvalidPublicKey:
        return "invalid public key";
      case SignatureVerifierErrc::InvalidSignature:
        return "invalid signature";
      case SignatureVerifierErrc::InternalFailure:
        return "internal failure";
      case SignatureVerifierErrc::Mismatch:
        return "signature mismatch";
      }
    return "(unknown)";
  }

  const SignatureVerifierErrorCategory globalSignatureVerifierErrorCategory{};
} // namespace

std::error_code
unfold::crypto::make_error_code(SignatureVerifierErrc ec)
{
  return std::error_code{static_cast<int>(ec), globalSignatureVerifierErrorCategory};
}
