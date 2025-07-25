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

#ifndef UPGRADE_INSTALLER_HH
#define UPGRADE_INSTALLER_HH

#include <memory>
#include <string>
#include <filesystem>

#include "http/HttpClient.hh"
#include "crypto/SignatureVerifier.hh"
#include "utils/Logging.hh"

#include "unfold/Unfold.hh"
#include "AppCast.hh"
#include "Platform.hh"
#include "Hooks.hh"
#include "Installer.hh"

class UpgradeInstaller : public Installer
{
public:
  explicit UpgradeInstaller(std::shared_ptr<Platform> platform,
                            std::shared_ptr<unfold::http::HttpClient> http,
                            std::shared_ptr<unfold::crypto::SignatureVerifier> verifier,
                            std::shared_ptr<Hooks> hooks);

  void set_download_progress_callback(unfold::Unfold::download_progress_callback_t callback) override;
  void set_installer_validation_callback(unfold::Unfold::installer_validation_callback_t callback) override;

  boost::asio::awaitable<outcome::std_result<void>> install(std::shared_ptr<AppcastItem> item) override;

private:
  outcome::std_result<std::filesystem::path> get_installer_filename();
  boost::asio::awaitable<outcome::std_result<void>> download_installer();
  boost::asio::awaitable<outcome::std_result<void>> verify_installer();
  boost::asio::awaitable<outcome::std_result<void>> run_installer();

  void fix_permissions();

private:
  std::shared_ptr<Platform> platform;
  std::shared_ptr<unfold::http::HttpClient> http;
  std::shared_ptr<unfold::crypto::SignatureVerifier> verifier;
  std::shared_ptr<Hooks> hooks;

  std::shared_ptr<AppcastItem> item;
  std::filesystem::path installer_path;
  unfold::Unfold::download_progress_callback_t progress_callback;
  unfold::Unfold::installer_validation_callback_t installer_validation_callback;
  unfold::Unfold::update_status_callback_t update_status_callback;
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:installer")};
};

#endif // UPGRADE_INSTALLER_HH
