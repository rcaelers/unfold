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

#include "SigstoreVerifier.hh"

#include <exception>
#include <memory>
#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>

#include "UnfoldErrors.hh"
#include "sigstore/Bundle.hh"

SigstoreVerifier::SigstoreVerifier(std::shared_ptr<sigstore::Context> context, std::shared_ptr<unfold::http::HttpClient> http)
  : context(std::move(context))
  , http(std::move(http))
{
}

boost::asio::awaitable<outcome::std_result<void>>
SigstoreVerifier::verify(std::string url, std::string data)
{
  if (!verification_enabled)
    {
      co_return outcome::success();
    }

  auto sigstore_bundle = co_await download_sigstore_bundle(url);
  if (!sigstore_bundle)
    {
      co_return sigstore_bundle.error();
    }

  co_return verify_sigstore(sigstore_bundle.value(), data);
}

boost::asio::awaitable<outcome::std_result<void>>
SigstoreVerifier::verify(std::string url, std::filesystem::path filename)
{
  if (!verification_enabled)
    {
      co_return outcome::success();
    }

  auto sigstore_bundle = co_await download_sigstore_bundle(url);
  if (!sigstore_bundle)
    {
      co_return sigstore_bundle.error();
    }

  co_return verify_sigstore(sigstore_bundle.value(), filename);
}

boost::asio::awaitable<outcome::std_result<std::shared_ptr<sigstore::Bundle>>>
SigstoreVerifier::download_sigstore_bundle(std::string url)
{
  logger->info("downloading sigstore bundle {}", url);

  auto rc = co_await http->get(url);
  if (!rc)
    {
      logger->error("failed to download sigstore bundle ({})", rc.error().message());
      co_return unfold::UnfoldErrc::SigstoreDownloadFailed;
    }

  auto [result, content] = rc.value();
  if (result != 200)
    {
      logger->error("failed to download sigstore bundle ({} {})", result, content);
      co_return unfold::UnfoldErrc::SigstoreDownloadFailed;
    }

  if (content.empty())
    {
      logger->error("failed to download sigstore bundle (empty)");
      co_return unfold::UnfoldErrc::InvalidSigstoreBundle;
    }

  auto sigstore_bundle_result = sigstore::Bundle::create(context, content);
  if (!sigstore_bundle_result)
    {
      logger->error("failed to create sigstore bundle ({})", sigstore_bundle_result.error().message());
      co_return unfold::UnfoldErrc::InvalidSigstoreBundle;
    }

  co_return sigstore_bundle_result;
}

outcome::std_result<void>
SigstoreVerifier::verify_sigstore(std::shared_ptr<sigstore::Bundle> sigstore_bundle, std::string data)
{
  if (!sigstore_bundle)
    {
      logger->error("sigstore bundle is empty");
      return unfold::UnfoldErrc::InvalidSigstoreBundle;
    }

  auto result = sigstore_bundle->verify(data);
  if (!result)
    {
      logger->error("failed to verify sigstore bundle ({})", result.error().message());
      return unfold::UnfoldErrc::SigstoreVerificationFailed;
    }

  if (validation_callback)
    {
      auto result = validation_callback(sigstore_bundle);
      if (!result)
        {
          logger->error("failed to validate sigstore bundle ({})", result.error().message());
          return result.error();
        }
      if (!result.value())
        {
          logger->error("failed to validate sigstore bundle");
          return unfold::UnfoldErrc::SigstoreVerificationFailed;
        }
    }

  logger->info("sigstore bundle verified successfully");
  return outcome::success();
}

outcome::std_result<void>
SigstoreVerifier::verify_sigstore(std::shared_ptr<sigstore::Bundle> sigstore_bundle, std::filesystem::path filename)
{
  try
    {
      auto mode = boost::interprocess::read_only;
      boost::interprocess::file_mapping fm(filename.c_str(), mode);
      boost::interprocess::mapped_region region(fm, mode, 0, 0);
      std::string data(static_cast<const char *>(region.get_address()), region.get_size());
      return verify_sigstore(sigstore_bundle, data);
    }
  catch (boost::interprocess::interprocess_exception &e)
    {
      logger->error("error loading file {}", e.what());
      return unfold::UnfoldErrc::SigstoreVerificationFailed;
    }
  catch (std::exception &e)
    {
      logger->error("error checking signature {}", e.what());
      return unfold::UnfoldErrc::SigstoreVerificationFailed;
    }
}

void
SigstoreVerifier::set_verification_enabled(bool enabled)
{
  verification_enabled = enabled;
}

void
SigstoreVerifier::set_validation_callback(unfold::Unfold::sigstore_validation_callback_t callback)
{
  validation_callback = std::move(callback);
}
