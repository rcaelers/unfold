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

#ifndef SIGNATURE_ALGORITHM_HH
#define SIGNATURE_ALGORITHM_HH

#include <string>
#include <string_view>
#include <memory>

#include <boost/outcome/std_result.hpp>

#include "crypto/SignatureAlgorithmType.hh"

namespace outcome = boost::outcome_v2;

class SignatureAlgorithm
{
public:
  virtual ~SignatureAlgorithm() = default;
  virtual outcome::std_result<void> set_key(const std::string &public_key) = 0;
  virtual outcome::std_result<void> verify(std::string_view data, const std::string &signature) = 0;
};

class SignatureAlgorithmFactory
{
public:
  static std::shared_ptr<SignatureAlgorithm> create(unfold::crypto::SignatureAlgorithmType type);
};

#endif // SIGNATURE_ALGORITHM_HH
