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

#ifndef CRYPTO_SIGNATURE_VERIFIER_ERRORS_HH
#define CRYPTO_SIGNATURE_VERIFIER_ERRORS_HH

#include <system_error>

namespace unfold::crypto
{
  enum class SignatureVerifierErrc
  {
    Success = 0,
    NotFound = 1,
    InvalidPublicKey = 2,
    InvalidSignature = 3,
    InternalFailure = 4,
    Mismatch = 5,
  };

  std::error_code make_error_code(SignatureVerifierErrc ec);
} // namespace unfold::crypto

namespace std
{
  template<>
  struct is_error_code_enum<unfold::crypto::SignatureVerifierErrc> : true_type
  {
  };
} // namespace std

#endif // CRYPTO_SIGNATURE_VERIFIER_ERRORS_HH
