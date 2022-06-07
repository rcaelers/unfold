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

#include "UpgradeControl.hh"

#include <chrono>
#include <exception>
#include <memory>
#include <utility>
#include <fstream>
#include <ranges>

#include <boost/range/adaptors.hpp>

#include <spdlog/fmt/ostr.h>

#include "AppCast.hh"
#include "Checker.hh"
#include "Installer.hh"
#include "Platform.hh"
#include "SettingsStorage.hh"

#include "unfold/Unfold.hh"
#include "unfold/UnfoldErrors.hh"

#include "crypto/SignatureVerifier.hh"
#include "http/HttpClient.hh"
#include "utils/PeriodicTimer.hh"
#include "utils/TempDirectory.hh"

#if defined(WIN32)
#  include "windows/WindowsPlatform.hh"
#else
#  include "DummyPlatform.hh"
#endif

std::shared_ptr<unfold::Unfold>
unfold::Unfold::create(unfold::utils::IOContext &io_context)
{
#if defined(WIN32)
  auto platform = std::make_shared<WindowsPlatform>();
#else
  auto platform = std::make_shared<DummyPlatform>();
#endif

  return std::make_shared<UpgradeControl>(platform, io_context);
}

UpgradeControl::UpgradeControl(std::shared_ptr<Platform> platform, unfold::utils::IOContext &io_context)
  : platform(platform)
  , http(std::make_shared<unfold::http::HttpClient>())
  , verifier(std::make_shared<unfold::crypto::SignatureVerifier>())
  , storage(SettingsStorage::create())
  , state(std::make_shared<Settings>(storage))
  , installer(std::make_shared<Installer>(platform, http, verifier))
  , checker(std::make_shared<Checker>(platform, http))
  , checker_timer(io_context.get_io_context())
{
  init_periodic_update_check();
}

UpgradeControl::UpgradeControl(std::shared_ptr<Platform> platform,
                               std::shared_ptr<unfold::http::HttpClient> http,
                               std::shared_ptr<unfold::crypto::SignatureVerifier> verifier,
                               std::shared_ptr<SettingsStorage> storage,
                               std::shared_ptr<Installer> installer,
                               std::shared_ptr<Checker> checker,
                               unfold::utils::IOContext &io_context)
  : platform(platform)
  , http(http)
  , verifier(verifier)
  , storage(storage)
  , state(std::make_shared<Settings>(storage))
  , installer(installer)
  , checker(checker)
  , checker_timer(io_context.get_io_context())
{
  init_periodic_update_check();
}

outcome::std_result<void>
UpgradeControl::set_appcast(const std::string &url)
{
  return checker->set_appcast(url);
}

outcome::std_result<void>
UpgradeControl::set_current_version(const std::string &version)
{
  return checker->set_current_version(version);
}

outcome::std_result<void>
UpgradeControl::set_signature_verification_key(const std::string &key)
{
  auto result = verifier->set_key(unfold::crypto::SignatureAlgorithmType::ECDSA, key);
  if (!result)
    {
      logger->error("invalid key '{}' ({})", key, result.error().message());
      return outcome::failure(unfold::UnfoldErrc::InvalidArgument);
    }
  return outcome::success();
}

outcome::std_result<void>
UpgradeControl::set_certificate(const std::string &cert)
{
  auto result = http->add_ca_cert(cert);
  if (!result)
    {
      logger->error("invalid ca certificate ({})", result.error().message());
      return outcome::failure(unfold::UnfoldErrc::InvalidArgument);
    }
  return outcome::success();
}

void
UpgradeControl::set_periodic_update_check_enabled(bool enabled)
{
  checker_timer.set_enabled(enabled);
}

void
UpgradeControl::set_periodic_update_check_interval(std::chrono::seconds interval)
{
  checker_timer.set_interval(interval);
}

void
UpgradeControl::set_configuration_prefix(const std::string &prefix)
{
  storage->set_prefix(prefix);
}

void
UpgradeControl::set_update_available_callback(update_available_callback_t callback)
{
  update_available_callback = callback;
}

std::optional<std::chrono::system_clock::time_point>
UpgradeControl::get_last_update_check_time()
{
  return state->get_last_update_check_time();
}

void
UpgradeControl::update_last_update_check_time()
{
  state->set_last_update_check_time(std::chrono::system_clock::now());
}

boost::asio::awaitable<outcome::std_result<bool>>
UpgradeControl::check_for_updates()
{
  update_last_update_check_time();
  co_return co_await checker->check_for_updates();
}

boost::asio::awaitable<outcome::std_result<void>>
UpgradeControl::check_for_updates_and_notify()
{
  auto rc = co_await check_for_updates();
  if (!rc)
    {
      logger->error("failed to check for updates: {}", rc.error().message());
      co_return rc.as_failure();
    }

  if (!rc.value())
    {
      logger->info("no update available");
      co_return outcome::success();
    }

  auto info = checker->get_update_info();
  if (!info)
    {
      co_return outcome::failure(unfold::UnfoldErrc::InternalError);
    }

  if (state->get_skip_version() == info->version)
    {
      logger->info("skipping update to version {}", info->version);
      co_return outcome::success();
    }

  if (!update_available_callback)
    {
      logger->info("update to version {} available, but nothing to notify", info->version);
      co_return outcome::success();
    }

  auto resp = co_await update_available_callback();
  switch (resp)
    {
    case unfold::UpdateResponse::Install:
      co_return co_await install_update();
      break;
    case unfold::UpdateResponse::Later:
      break;
    case unfold::UpdateResponse::Skip:
      state->set_skip_version(info->version);
      break;
    }

  co_return outcome::success();
}

boost::asio::awaitable<outcome::std_result<void>>
UpgradeControl::install_update()
{
  auto selected_update = checker->get_selected_update();
  co_return co_await installer->install(selected_update);
}

std::shared_ptr<unfold::UpdateInfo>
UpgradeControl::get_update_info() const
{
  return checker->get_update_info();
}

void
UpgradeControl::init_periodic_update_check()
{
  checker_timer.set_callback([this]() -> boost::asio::awaitable<void> {
    auto rc = co_await check_for_updates_and_notify();
    if (!rc)
      {
        logger->error("failed to check for updates: {}", rc.error().message());
      }
  });
}
