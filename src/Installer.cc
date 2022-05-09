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

#include "Installer.hh"

#include <exception>
#include <memory>
#include <utility>
#include <fstream>
#include <spdlog/fmt/ostr.h>

#include "crypto/SignatureVerifier.hh"
#include "utils/TempDirectory.hh"

#include "Platform.hh"

Installer::Installer(std::shared_ptr<Platform> platform,
                     std::shared_ptr<unfold::http::HttpClient> http,
                     std::shared_ptr<unfold::crypto::SignatureVerifier> verifier)
  : platform(std::move(platform))
  , http(std::move(http))
  , verifier(std::move(verifier))
{
}

void
Installer::install(std::shared_ptr<AppcastEnclosure> enclosure)
{
  try
    {
      this->enclosure = enclosure;

      unfold::utils::TempDirectory temp_dir;
      installer_path = temp_dir.get_path() / "install.exe"; // TODO:

      download_installer();
      verify_installer();
      run_installer();
    }
  catch (std::exception &e)
    {
      logger->error("failed to install update ({})", e.what());
    }
}

void
Installer::download_installer()
{
  try
    {
      logger->info("path {}", installer_path.string());
      std::ofstream out_file(installer_path.string(), std::ofstream::binary);

      auto rc = http->get_sync(enclosure->url, out_file, [&](double progress) {});
      auto [result, content] = rc.value();

      out_file.close();
    }
  catch (std::exception &e)
    {
      logger->error("failed to download ({})", e.what());
    }
}

void
Installer::verify_installer()
{
  try
    {
      std::error_code ec;
      std::uintmax_t size = std::filesystem::file_size(installer_path, ec);
      if (ec)
        {
          logger->error("could not get installer file size ({})", ec.message());
        }

      if (enclosure->length != size)
        {
          logger->error("incorrect installer file size ({} instead of {})", enclosure->length, size);
        }

      auto result = verifier->verify(installer_path.string(), enclosure->signature);
      if (result.error() != unfold::crypto::SignatureVerifierErrc::Success)
        {
          logger->error("certificate incorrect ({})");
        }
    }
  catch (std::exception &e)
    {
      logger->error("failed to verify ({})", e.what());
    }
}

void
Installer::run_installer()
{
  try
    {
    }
  catch (std::exception &e)
    {
      logger->error("failed to execute installer ({})", e.what());
    }
}
