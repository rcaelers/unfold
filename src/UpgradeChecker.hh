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

#ifndef UPGRADE_CHECKER_HH
#define UPGRADE_CHECKER_HH

#include <memory>
#include <string>
#include <filesystem>

#include "unfold/Unfold.hh"
#include "http/HttpClient.hh"
#include "crypto/SignatureVerifier.hh"
#include "utils/Logging.hh"

#include "AppCast.hh"
#include "Platform.hh"
#include "Hooks.hh"
#include "Checker.hh"

class UpgradeChecker : public Checker
{
public:
  explicit UpgradeChecker(std::shared_ptr<Platform> platform,
                          std::shared_ptr<unfold::http::HttpClient> http,
                          std::shared_ptr<Hooks> hooks);

  boost::asio::awaitable<outcome::std_result<bool>> check_for_updates() override;

  outcome::std_result<void> set_appcast(const std::string &url) override;
  outcome::std_result<void> set_current_version(const std::string &version) override;

  std::shared_ptr<unfold::UpdateInfo> get_update_info() const override;
  std::shared_ptr<AppcastItem> get_selected_update() const override;

private:
  boost::asio::awaitable<outcome::std_result<std::string>> download_appcast();
  outcome::std_result<std::shared_ptr<Appcast>> parse_appcast(const std::string &appcast_xml);
  void build_update_info(std::shared_ptr<Appcast> appcast);
  bool is_applicable(std::shared_ptr<AppcastItem> item);

private:
  std::shared_ptr<Platform> platform;
  std::shared_ptr<unfold::http::HttpClient> http;
  std::shared_ptr<Hooks> hooks;

  std::string appcast_url;
  std::string current_version_str;
  semver::version current_version;

  std::shared_ptr<AppcastItem> selected_item;
  std::shared_ptr<unfold::UpdateInfo> update_info;

  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:checker")};
};

#endif // UPGRADE_CHECKER_HH
