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

#include "UpgradeInstaller.hh"

#include <exception>
#include <memory>
#include <system_error>
#include <utility>
#include <fstream>
#include <spdlog/fmt/ostr.h>
#include <vector>

#include <boost/outcome/try.hpp>
#include <boost/url/url.hpp>
#include <boost/url/parse.hpp>
#include <boost/process.hpp>

#include "UnfoldErrors.hh"
#include "crypto/SignatureVerifier.hh"
#include "utils/TempDirectory.hh"

#include "Platform.hh"

UpgradeInstaller::UpgradeInstaller(std::shared_ptr<Platform> platform,
                                   std::shared_ptr<unfold::http::HttpClient> http,
                                   std::shared_ptr<unfold::crypto::SignatureVerifier> verifier,
                                   std::shared_ptr<Hooks> hooks)
  : platform(std::move(platform))
  , http(std::move(http))
  , verifier(std::move(verifier))
  , hooks(std::move(hooks))
{
}

void
UpgradeInstaller::set_download_progress_callback(unfold::Unfold::download_progress_callback_t callback)
{
  this->progress_callback = callback;
}

boost::asio::awaitable<outcome::std_result<void>>
UpgradeInstaller::install(std::shared_ptr<AppcastItem> item)
{
  this->item = item;

  unfold::utils::TempDirectory temp_dir;

  BOOST_OUTCOME_CO_TRY(auto filename, get_installer_filename());

  installer_path = temp_dir.get_path() / filename;

  BOOST_OUTCOME_CO_TRYV(co_await download_installer());
  BOOST_OUTCOME_CO_TRYV(co_await verify_installer());
  BOOST_OUTCOME_CO_TRYV(co_await run_installer());

  co_return outcome::success();
}

outcome::std_result<std::filesystem::path>
UpgradeInstaller::get_installer_filename()
{
  auto r = boost::urls::parse_uri(item->enclosure->url);
  if (r.has_value())
    {
      std::string_view path = r.value().encoded_path();
      std::filesystem::path p{path};
      return outcome::success(p.filename());
    }

  logger->info("failed to extract installer filename from URL ({})", r.error().message());
  return outcome::failure(unfold::UnfoldErrc::InstallerDownloadFailed);
}

boost::asio::awaitable<outcome::std_result<void>>
UpgradeInstaller::download_installer()
{
  try
    {
      logger->info("downloading {} to {}", item->enclosure->url, installer_path.string());
      std::ofstream out_file(installer_path.string(), std::ofstream::binary);

      auto rc = co_await http->get(item->enclosure->url, out_file, [&](double progress) {
        if (progress_callback)
          {
            progress_callback(progress);
          }
      });
      if (!rc)
        {
          logger->error("failed to download installer {} ({})", item->enclosure->url, rc.error());
          co_return outcome::failure(unfold::UnfoldErrc::InstallerDownloadFailed);
        }
      auto [result, content] = rc.value();
      if (result != 200)
        {
          logger->error("failed to download installer {} ({} {})", item->enclosure->url, result, content);
          co_return outcome::failure(unfold::UnfoldErrc::InstallerDownloadFailed);
        }

      out_file.close();
    }
  catch (std::exception &e)
    {
      logger->error("failed to download installer {} ({})", item->enclosure->url, e.what());
      co_return outcome::failure(unfold::UnfoldErrc::InstallerDownloadFailed);
    }
  co_return outcome::success();
}

boost::asio::awaitable<outcome::std_result<void>>
UpgradeInstaller::verify_installer()
{
  std::error_code ec;
  std::uintmax_t size = std::filesystem::file_size(installer_path, ec);
  if (ec)
    {
      logger->error("could not get installer ({}) file size ({})", installer_path.string(), ec.message());
      co_return outcome::failure(unfold::UnfoldErrc::InstallerVerificationFailed);
    }

  if (item->enclosure->length != size)
    {
      logger->error("incorrect installer file size ({} instead of {})", size, item->enclosure->length);
      co_return outcome::failure(unfold::UnfoldErrc::InstallerVerificationFailed);
    }

  auto rc = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(outcome::std_result<void>)>(
    [this](auto &&self) {
      std::thread([this, self = std::move(self)]() mutable {
        auto result = verifier->verify(installer_path.string(), item->enclosure->signature);
        self.complete(result);
      }).detach();
    },
    boost::asio::use_awaitable);

  if (!rc)
    {
      logger->error("signature failure ({})", rc.error().message());
      co_return outcome::failure(unfold::UnfoldErrc::InstallerVerificationFailed);
    }

  co_return rc;
}

void
UpgradeInstaller::fix_permissions()
{
#if !defined(_WIN32)
  std::error_code ec;
  std::filesystem::permissions(installer_path.string(),
                               std::filesystem::perms::owner_exec,
                               std::filesystem::perm_options::add,
                               ec);
  if (ec)
    {
      logger->error("failed to make installer {} executable ({})", installer_path.string(), ec.message());
    }
#endif
}

boost::asio::awaitable<outcome::std_result<void>>
UpgradeInstaller::run_installer()
{
  fix_permissions();

  try
    {
      logger->info("running installer {} (args-{})", installer_path.string(), item->enclosure->installer_arguments);
      std::vector<std::string> args;
      boost::split(args, item->enclosure->installer_arguments, boost::is_any_of(" "));
      boost::process::spawn(installer_path.string(), args);
      logger->info("installer finished");
    }
  catch (std::exception &e)
    {
      logger->error("failed to run installer {}  ({})", installer_path.string(), e.what());
      co_return outcome::failure(unfold::UnfoldErrc::InstallerExecutionFailed);
    }

  bool do_terminate = true;
  if (hooks->hook_terminate())
    {
      do_terminate = hooks->hook_terminate()();
    }

  if (do_terminate)
    {
      platform->terminate();
    }

  co_return outcome::success();
}
