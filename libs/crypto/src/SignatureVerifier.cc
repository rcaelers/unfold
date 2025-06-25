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

#include "crypto/SignatureVerifier.hh"

#include <exception>
#include <memory>
#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include "utils/Base64.hh"
#include "crypto/SignatureVerifierErrors.hh"
#include "SignatureAlgorithm.hh"

using namespace unfold::crypto;

outcome::std_result<void>
SignatureVerifier::set_key(SignatureAlgorithmType type, const std::string &public_key)
{
  algo = SignatureAlgorithmFactory::create(type);
  return algo->set_key(public_key);
}

outcome::std_result<void>
SignatureVerifier::verify(const std::string &filename, const std::string &signature)
{
  if (!algo)
    {
      logger->error("no algorithm configured");
      return SignatureVerifierErrc::InvalidPublicKey;
    }

  if (signature.empty())
    {
      logger->error("signature empty");
      return SignatureVerifierErrc::InvalidSignature;
    }

  try
    {
      auto mode = boost::interprocess::read_only;
      boost::interprocess::file_mapping fm(filename.c_str(), mode);
      boost::interprocess::mapped_region region(fm, mode, 0, 0);
      std::string_view data(static_cast<const char *>(region.get_address()), region.get_size());

      return algo->verify(data, unfold::utils::Base64::decode(signature));
    }
  catch (boost::interprocess::interprocess_exception &e)
    {
      logger->error("error loading file {}", e.what());
      return SignatureVerifierErrc::NotFound;
    }
  catch (std::exception &e)
    {
      logger->error("error checking signature {}", e.what());
      return SignatureVerifierErrc::Mismatch;
    }

  return SignatureVerifierErrc::Mismatch;
}
