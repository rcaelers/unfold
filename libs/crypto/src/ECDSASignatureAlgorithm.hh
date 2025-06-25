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

#ifndef ECDSA_SIGNATURE_ALGORITHM_HH
#define ECDSA_SIGNATURE_ALGORITHM_HH

#include "SignatureAlgorithm.hh"

#include <memory>

#include "PublicKey.hh"
#include "utils/Logging.hh"

class ECDSASignatureAlgorithm : public SignatureAlgorithm
{
public:
  ECDSASignatureAlgorithm() = default;
  ~ECDSASignatureAlgorithm() override = default;

  outcome::std_result<void> set_key(const std::string &public_key) override;
  outcome::std_result<void> verify(std::string_view data, const std::string &signature) override;

private:
  std::unique_ptr<PublicKey> public_key;
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:crypto:ecdsa")};
};

#endif // ECDSA_SIGNATURE_ALGORITHM_HH
