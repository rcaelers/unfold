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

#include "Checker.hh"
#include "utils/PeriodicTimer.hh"
#include "Unfold.hh"
#include "crypto/SignatureVerifier.hh"
#include "http/HttpClient.hh"
#include "utils/TempDirectory.hh"
#include "unfold/UnfoldErrors.hh"

#include "AppCast.hh"
#include "Installer.hh"
#include "Platform.hh"

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
  , installer(std::make_shared<Installer>(platform, http, verifier))
  , checker(std::make_shared<Checker>(platform, http))
  , checker_timer(io_context.get_io_context())
{
  checker_timer.set_callback([this]() -> boost::asio::awaitable<void> {
    auto rc = co_await check_for_updates_and_notify();
    if (!rc)
      {
        logger->error("failed to check for updates: {}", rc.error().message());
      }
  });
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
      logger->error("invalid key '{}' ({})");
      return outcome::failure(unfold::UnfoldErrc::InvalidArgument);
    }
  return outcome::success();
}

outcome::std_result<void>
UpgradeControl::set_certificate(const std::string &cert)
{
  http->add_ca_cert(cert);
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
  configuration_prefix = prefix;
}

void
UpgradeControl::set_update_available_callback(update_available_callback_t callback)
{
  update_available_callback = callback;
}

std::chrono::system_clock::time_point
UpgradeControl::get_last_update_check_time()
{
  return last_update_check_time;
}

boost::asio::awaitable<outcome::std_result<bool>>
UpgradeControl::check_for_updates()
{
  last_update_check_time = std::chrono::system_clock::now();
  co_return co_await checker->check_for_updates();
}

boost::asio::awaitable<outcome::std_result<void>>
UpgradeControl::check_for_updates_and_notify()
{
  auto rc = co_await check_for_updates();
  if (!rc)
    {
      co_return rc.as_failure();
    }

  if (rc.value() && update_available_callback)
    {
      co_await update_available_callback();
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
