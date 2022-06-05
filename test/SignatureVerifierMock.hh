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

#ifndef SIGNATURE_VERIFIER_MOCK_HH
#define SIGNATURE_VERIFIER_MOCK_HH

#include <string>
#include <string_view>
#include <memory>

#include "gmock/gmock.h"

#include <boost/outcome/std_result.hpp>

#include "crypto/SignatureAlgorithmType.hh"
#include "crypto/SignatureVerifier.hh"
#include "crypto/SignatureVerifierErrors.hh"
#include "utils/Logging.hh"

namespace outcome = boost::outcome_v2;

class SignatureAlgorithm;

class SignatureVerifierMock : public unfold::crypto::SignatureVerifier
{
public:
  SignatureVerifierMock() = default;

  MOCK_METHOD(outcome::std_result<void>,
              set_key,
              (unfold::crypto::SignatureAlgorithmType type, const std::string &public_key),
              (override));
  MOCK_METHOD(outcome::std_result<void>, verify, (const std::string &filename, const std::string &signature), (override));
};

#endif // SIGNATURE_VERIFIER_MOCK_HH
