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

#ifndef CRYPTOGRAPHIC_ALGORITHMS_HH
#define CRYPTOGRAPHIC_ALGORITHMS_HH

#include <string>
#include <boost/outcome/std_result.hpp>

namespace outcome = boost::outcome_v2;

namespace unfold::sigstore
{
  enum class KeyAlgorithm
  {
    Unknown,
    RSA,
    ECDSA,
    EdDSA
  };

  enum class DigestAlgorithm
  {
    SHA1,
    SHA256,
    SHA384,
    SHA512
  };

  outcome::std_result<DigestAlgorithm> digest_algorithm_from_string(const std::string &algorithm_name);

} // namespace unfold::sigstore

#endif // CRYPTOGRAPHIC_ALGORITHMS_HH
