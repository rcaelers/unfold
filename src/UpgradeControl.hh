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

#ifndef UPGRADE_CONTROL_HH
#define UPGRADE_CONTROL_HH

#include <memory>
#include <string>
#include <filesystem>
#include <chrono>

#include "AppCast.hh"
#include "SettingsStorage.hh"
#include "unfold/Unfold.hh"

#include "http/HttpClient.hh"
#include "utils/Logging.hh"
#include "unfold/coro/IOContext.hh"
#include "utils/PeriodicTimer.hh"

#include "Platform.hh"
#include "UpgradeInstaller.hh"
#include "UpgradeChecker.hh"
#include "Settings.hh"
#include "Hooks.hh"

#include "semver.hpp"

class UpgradeControl : public unfold::Unfold
{
public:
  UpgradeControl(std::shared_ptr<Platform> platform, unfold::coro::IOContext &io_context);

  UpgradeControl(std::shared_ptr<Platform> platform,
                 std::shared_ptr<unfold::http::HttpClient> http,
                 std::shared_ptr<unfold::crypto::SignatureVerifier> verifier,
                 std::shared_ptr<SettingsStorage> storage,
                 std::shared_ptr<Installer> installer,
                 std::shared_ptr<Checker> checker,
                 unfold::coro::IOContext &io_context);

  outcome::std_result<void> set_appcast(const std::string &url) override;
  outcome::std_result<void> set_current_version(const std::string &version) override;
  outcome::std_result<void> set_signature_verification_key(const std::string &key) override;
  outcome::std_result<void> set_certificate(const std::string &cert) override;
  void set_periodic_update_check_enabled(bool enabled) override;
  void set_periodic_update_check_interval(std::chrono::seconds interval) override;
  void set_configuration_prefix(const std::string &prefix) override;
  void set_update_available_callback(update_available_callback_t callback) override;
  void set_download_progress_callback(download_progress_callback_t callback) override;
  std::optional<std::chrono::system_clock::time_point> get_last_update_check_time() override;

  boost::asio::awaitable<outcome::std_result<bool>> check_for_updates() override;
  boost::asio::awaitable<outcome::std_result<void>> install_update() override;
  std::shared_ptr<unfold::UpdateInfo> get_update_info() const override;
  std::shared_ptr<unfold::UnfoldHooks> get_hooks() const override;

  boost::asio::awaitable<outcome::std_result<void>> check_for_updates_and_notify();

  void reset_skip_version();
  std::string get_skip_version() const;

private:
  void init_periodic_update_check();
  void update_last_update_check_time();

private:
  std::shared_ptr<Platform> platform;
  std::shared_ptr<unfold::http::HttpClient> http;
  std::shared_ptr<unfold::crypto::SignatureVerifier> verifier;
  std::shared_ptr<Hooks> hooks;
  std::shared_ptr<SettingsStorage> storage;
  std::shared_ptr<Settings> state;
  std::shared_ptr<Installer> installer;
  std::shared_ptr<Checker> checker;

  unfold::utils::PeriodicTimer checker_timer;

  update_available_callback_t update_available_callback;

  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:control")};
};

#endif // UPGRADE_CONTROL_HH
