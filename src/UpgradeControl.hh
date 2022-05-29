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

#include "AppCast.hh"
#include "unfold/Unfold.hh"

#include "http/HttpClient.hh"
#include "utils/Logging.hh"

#include "Platform.hh"
#include "Installer.hh"

#include "semver.hpp"

class UpgradeControl : public unfold::Unfold
{
public:
  explicit UpgradeControl(std::shared_ptr<Platform> platform);

  outcome::std_result<void> set_appcast(const std::string &url) override;
  outcome::std_result<void> set_current_version(const std::string &version) override;
  outcome::std_result<void> set_signature_verification_key(const std::string &key) override;

  outcome::std_result<void> set_certificate(const std::string &cert) override;

  boost::asio::awaitable<outcome::std_result<bool>> check() override;
  boost::asio::awaitable<outcome::std_result<void>> install() override;
  std::shared_ptr<unfold::UpdateInfo> get_update_info() const override;

private:
  boost::asio::awaitable<outcome::std_result<std::string>> download_appcast();
  outcome::std_result<std::shared_ptr<Appcast>> parse_appcast(const std::string &appcast_xml);
  void build_update_info(std::shared_ptr<Appcast> appcast);
  bool is_applicable(std::shared_ptr<AppcastItem> item);

private:
  std::shared_ptr<Platform> platform;
  std::shared_ptr<unfold::http::HttpClient> http;
  std::shared_ptr<unfold::crypto::SignatureVerifier> verifier;
  Installer installer;

  std::string appcast_url;
  std::string current_version_str;
  semver::version current_version;
  std::shared_ptr<AppcastItem> selected_item;
  std::shared_ptr<unfold::UpdateInfo> update_info;

  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:control")};
};

#endif // UPGRADE_CONTROL_HH
