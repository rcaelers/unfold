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
#include <random>
#include <utility>
#include <fstream>
#include <ranges>

#include <boost/range/adaptors.hpp>

#include <spdlog/fmt/ostr.h>

#include "AppCast.hh"
#include "UpgradeChecker.hh"
#include "UpgradeInstaller.hh"
#include "Platform.hh"
#include "Settings.hh"
#include "SettingsStorage.hh"

#include "unfold/Unfold.hh"
#include "unfold/UnfoldErrors.hh"

#include "crypto/SignatureVerifier.hh"
#include "http/HttpClient.hh"
#include "utils/TempDirectory.hh"
#include "utils/TimeSource.hh"

// TODO: move to different file
#if defined(WIN32)
#  include "windows/WindowsPlatform.hh"
std::shared_ptr<unfold::Unfold>
unfold::Unfold::create(unfold::coro::IOContext &io_context)
{
  auto platform = std::make_shared<WindowsPlatform>();
  return std::make_shared<UpgradeControl>(platform, io_context);
}
#endif

UpgradeControl::UpgradeControl(std::shared_ptr<Platform> platform, unfold::coro::IOContext &io_context)
  : platform(platform)
  , http(std::make_shared<unfold::http::HttpClient>())
  , verifier(std::make_shared<unfold::crypto::SignatureVerifier>())
  , hooks(std::make_shared<Hooks>())
  , storage(SettingsStorage::create())
  , state(std::make_shared<Settings>(storage))
  , installer(std::make_shared<UpgradeInstaller>(platform, http, verifier, hooks))
  , checker(std::make_shared<UpgradeChecker>(platform, http, hooks))
  , time_source(std::make_shared<unfold::utils::RealTimeSource>())
  , check_timer(io_context.get_io_context())
{
  http->options().set_timeout(std::chrono::seconds(30));
  http->options().set_max_redirects(5);
  http->options().set_follow_redirects(true);
  init_periodic_update_check();
  init_priority();
}

UpgradeControl::UpgradeControl(std::shared_ptr<Platform> platform,
                               std::shared_ptr<unfold::http::HttpClient> http,
                               std::shared_ptr<unfold::crypto::SignatureVerifier> verifier,
                               std::shared_ptr<SettingsStorage> storage,
                               std::shared_ptr<Installer> installer,
                               std::shared_ptr<Checker> checker,
                               std::shared_ptr<unfold::utils::TimeSource> time_source,
                               unfold::coro::IOContext &io_context)
  : platform(std::move(platform))
  , http(std::move(http))
  , verifier(std::move(verifier))
  , hooks(std::make_shared<Hooks>())
  , storage(storage)
  , state(std::make_shared<Settings>(storage))
  , installer(std::move(installer))
  , checker(std::move(checker))
  , time_source(std::move(time_source))
  , check_timer(io_context.get_io_context())
{
  init_periodic_update_check();
  init_priority();
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
UpgradeControl::set_allowed_channels(const std::vector<std::string> &channels)
{
  return checker->set_allowed_channels(channels);
}

outcome::std_result<void>
UpgradeControl::set_signature_verification_key(const std::string &key)
{
  auto result = verifier->set_key(unfold::crypto::SignatureAlgorithmType::ECDSA, key);
  if (!result)
    {
      logger->error("invalid signature verification key '{}' ({})", key, result.error().message());
      return outcome::failure(unfold::UnfoldErrc::InvalidArgument);
    }
  return outcome::success();
}

void
UpgradeControl::set_certificate(const std::string &cert)
{
  http->options().add_ca_cert(cert);
}

outcome::std_result<void>
UpgradeControl::set_priority(int priority)
{
  if (priority < 1 || priority > 100)
    {
      return outcome::failure(unfold::UnfoldErrc::InvalidArgument);
    }
  custom_priority = priority;
  return outcome::success();
}

void
UpgradeControl::unset_priority()
{
  custom_priority.reset();
}

void
UpgradeControl::set_periodic_update_check_enabled(bool enabled)
{
  if (periodic_update_check_enabled != enabled)
    {
      periodic_update_check_enabled = enabled;
      update_check_timer();
    }
}

void
UpgradeControl::set_periodic_update_check_interval(std::chrono::seconds interval)
{
  periodic_update_check_interval = interval;
}

void
UpgradeControl::set_configuration_prefix(const std::string &prefix)
{
  auto rc = storage->set_prefix(prefix);
  if (!rc)
    {
      logger->error("failed to set configuration prefix '{}' ({})", prefix, rc.error().message());
    }
}

void
UpgradeControl::set_update_available_callback(update_available_callback_t callback)
{
  update_available_callback = callback;
}

void
UpgradeControl::set_download_progress_callback(download_progress_callback_t callback)
{
  installer->set_download_progress_callback(callback);
}

void
UpgradeControl::set_update_status_callback(update_status_callback_t callback)
{
  update_status_callback = callback;
}

std::optional<std::chrono::system_clock::time_point>
UpgradeControl::get_last_update_check_time()
{
  return state->get_last_update_check_time();
}

void
UpgradeControl::update_last_update_check_time()
{
  state->set_last_update_check_time(time_source->now());
}

boost::asio::awaitable<outcome::std_result<bool>>
UpgradeControl::check_for_update()
{
  update_last_update_check_time();
  auto rc = co_await checker->check_for_update();
  update_check_timer();
  co_return rc;
}

boost::asio::awaitable<outcome::std_result<void>>
UpgradeControl::check_for_update_and_notify()
{
  auto rc = co_await check_for_update_and_notify(true);
  if (update_status_callback && rc.has_error())
    {
      update_status_callback(rc.as_failure());
    }
  co_return rc;
}

boost::asio::awaitable<outcome::std_result<void>>
UpgradeControl::check_for_update_and_notify(bool manual)
{
  logger->info("checking for updates");
  check_timer.cancel();

  auto rc = co_await check_for_update();
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
      logger->error("failed to get update info");
      co_return outcome::failure(unfold::UnfoldErrc::InternalError);
    }

  if (!manual && state->get_skip_version() == info->version)
    {
      logger->info("skipping update to version {}", info->version);
      co_return outcome::success();
    }

  if (!manual && !is_ready_for_rollout())
    {
      logger->info("postponing update to version {}", info->version);
      co_return outcome::success();
    }

  if (!update_available_callback)
    {
      logger->error("update to version {} available, but nothing to notify", info->version);
      co_return outcome::failure(unfold::UnfoldErrc::InvalidArgument);
    }

  auto resp = co_await update_available_callback();
  switch (resp)
    {
    case unfold::UpdateResponse::Install:
      update_check_timer();
      co_return co_await install_update();
    case unfold::UpdateResponse::Later:
      reset_skip_version();
      break;
    case unfold::UpdateResponse::Skip:
      state->set_skip_version(info->version);
      break;
    }

  update_check_timer();
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

std::shared_ptr<unfold::UnfoldHooks>
UpgradeControl::get_hooks() const
{
  return hooks;
}

std::string
UpgradeControl::get_skip_version() const
{
  return state->get_skip_version();
}

void
UpgradeControl::reset_skip_version()
{
  state->set_skip_version("");
}

void
UpgradeControl::update_check_timer()
{
  if (!periodic_update_check_enabled)
    {
      check_timer.cancel();
      return;
    }

  auto now = time_source->now();
  auto last_check = get_last_update_check_time();
  if (!last_check || *last_check > now)
    {
      last_check = now;
    }

  auto next_check = *last_check + periodic_update_check_interval;
  if (next_check > now)
    {
      auto delay = next_check - now;
      logger->info("scheduling next update check in {} seconds", std::chrono::duration_cast<std::chrono::seconds>(delay).count());
      check_timer.schedule(delay);
    }
  else
    {
      logger->info("scheduling next update check immediately");
      check_timer.schedule(std::chrono::seconds(1));
    }
}

void
UpgradeControl::init_periodic_update_check()
{
  check_timer.set_callback([this]() -> boost::asio::awaitable<void> {
    logger->info("periodic update check triggered");
    auto rc = co_await check_for_update_and_notify(false);
    if (!rc)
      {
        logger->error("failed to perform periodic check for updates: {}", rc.error().message());
      }

    if (update_status_callback && rc.has_error())
      {
        update_status_callback(rc.as_failure());
      }

    update_check_timer();
  });
}

void
UpgradeControl::init_priority()
{
  int priority = state->get_priority();
  logger->info("current priority: {}", priority);
  if (priority == 0)
    {
      std::random_device rd;
      std::mt19937 gen(rd());
      std::uniform_int_distribution<> dis(1, 100);
      priority = dis(gen);
      state->set_priority(priority);
    }
}

int
UpgradeControl::get_priority() const
{
  if (custom_priority)
    {
      return *custom_priority;
    }
  return state->get_priority();
}

bool
UpgradeControl::is_ready_for_rollout()
{
  auto priority = get_priority();
  auto earliest_time = checker->get_earliest_rollout_time_for_priority(priority);

  return time_source->now() >= earliest_time;
}

void
UpgradeControl::set_proxy(unfold::ProxyType proxy)
{
  switch (proxy)
    {
    case unfold::ProxyType::None:
      http->options().set_proxy(unfold::http::Options::ProxyType::None);
      break;
    case unfold::ProxyType::System:
      http->options().set_proxy(unfold::http::Options::ProxyType::System);
      break;
    case unfold::ProxyType::Custom:
      http->options().set_proxy(unfold::http::Options::ProxyType::Custom);
      break;
    }
}

void
UpgradeControl::set_custom_proxy(const std::string &proxy)
{
  http->options().set_custom_proxy(proxy);
}
