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

#include <algorithm>
#include <fstream>
#include <memory>

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/outcome/success_failure.hpp>
#include <spdlog/spdlog.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "unfold/Unfold.hh"
#include "unfold/UnfoldErrors.hh"
#include "http/HttpServer.hh"
#include "utils/Base64.hh"

#include "TestBase.hh"
#include "TestPlatform.hh"
#include "UpgradeControl.hh"

namespace
{
  // openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 10000 -out cert.pem -subj "/CN=localhost"
  std::string const cert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICpDCCAYwCCQDU+pQ3ZUD30jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n"
    "b2NhbGhvc3QwHhcNMjIwNDE3MjE0MjMzWhcNNDkwOTAyMjE0MjMzWjAUMRIwEAYD\n"
    "VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDV\n"
    "r4sAS/gBsfurDLk6A9O+cZnaSH4zWvOXXmGRHSjgAQYMyVZ9sLVXn9Odmj+h6Qg0\n"
    "XMY4AzO/gATqF2voW1CtlPIcSa7eJPki3TD/UUn3ToYn11rfSaXjYB41FBCubp5y\n"
    "4S5Fg2GsWM1/5GYfLixzK2rM+DirEc05xjAqUWMtKFDXyD1O6KfOoeaq5qw5EojR\n"
    "9Ziu4K29cS6c9tze1Q4AXtVDdzNTypaC0RD+orNsZPQqIAfDfnAhwaJcsRlnGGf5\n"
    "iGe0jqJ+lThKsPO3x66nga66IqW1qe6OOs9MLAkZN92mXhS77qQeumi1hIYmUn3S\n"
    "EkydgQOzJTnlgmb8D9P1AgMBAAEwDQYJKoZIhvcNAQELBQADggEBADBotTUWDZTM\n"
    "aY/NX7/CkE2CnEP18Ccbv21edY+0UBy7L4lWBtLcvHZJ1HaFq4T4FfwvD+nNbRVM\n"
    "Up8j6rCFMKr/4tsD0UcKdBphDESpk0lq7uKPF3H2sU4sEnzQ/YI/IIT1gcp8iJLZ\n"
    "O+i0ur4CaTmPXF7oJXmAb0sIvUTQe+FXNvb4urqJ97Bu09vLmRkUvqmtELj1hDtf\n"
    "6vGcoQe5C/YsLNkcH1bvntxBT4bW7k47JSbPVKC7JHv2Z4u1Gj6TeQ6wUKRdjWtl\n"
    "Loe2vQ1h9EN6DxhmR7/Nc0sEKaYoJUbbufH+TcdzBqofOOZCBVNQNcQJyqvNpIs0\n"
    "KNdZa9scQjs=\n"
    "-----END CERTIFICATE-----\n";
} // namespace

namespace
{
  template<class T>
  struct Deleter;

  template<>
  struct Deleter<BIO>
  {
    void operator()(BIO *p) const
    {
      BIO_free_all(p);
    }
  };

  template<>
  struct Deleter<EVP_MD_CTX>
  {
    void operator()(EVP_MD_CTX *p) const
    {
      EVP_MD_CTX_free(p);
    }
  };

  template<>
  struct Deleter<EVP_PKEY>
  {
    void operator()(EVP_PKEY *p) const
    {
      EVP_PKEY_free(p);
    }
  };

  template<class Type>
  using UniquePtr = std::unique_ptr<Type, Deleter<Type>>;

  std::string sign(const std::string &msg, const std::string &priv_key)
  {
    UniquePtr<BIO> buff{BIO_new_mem_buf(priv_key.data(), static_cast<int>(priv_key.length()))};
    BIO_set_close(buff.get(), BIO_CLOSE);

    UniquePtr<EVP_PKEY> key{PEM_read_bio_PrivateKey(buff.get(), nullptr, nullptr, nullptr)};
    if (key == nullptr)
      {
        spdlog::error("Failed to read private key");
        return "";
      }

    UniquePtr<EVP_MD_CTX> ctx{EVP_MD_CTX_new()};
    if (ctx == nullptr)
      {
        spdlog::error("Failed to create EVP_MD_CTX");
        return "";
      }

    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1)
      {
        spdlog::error("Failed to init EVP_MD_CTX");
        return "";
      }

    std::size_t signature_len{0};
    if (EVP_DigestSign(ctx.get(), nullptr, &signature_len, reinterpret_cast<const unsigned char *>(msg.data()), msg.length())
        != 1)
      {
        spdlog::error("Failed to get signature length");
        return "";
      }

    std::vector<unsigned char> signature_buffer(signature_len);
    if (EVP_DigestSign(ctx.get(),
                       signature_buffer.data(),
                       &signature_len,
                       reinterpret_cast<const unsigned char *>(msg.data()),
                       msg.length())
        != 1)
      {
        spdlog::error("Failed to sign message");
        return "";
      }

    std::string signature(signature_buffer.begin(), signature_buffer.end());

    spdlog::info("Signature: {} {}", signature_len, unfold::utils::Base64::encode(signature));
    return unfold::utils::Base64::encode(signature);
  }

} // namespace

struct IntegrationTestFixture
{
  IntegrationTestFixture()
  {
    platform = std::make_shared<TestPlatform>();
  }

  ~IntegrationTestFixture()
  {
    server.stop();
  }

  IntegrationTestFixture(const IntegrationTestFixture &) = delete;
  IntegrationTestFixture &operator=(const IntegrationTestFixture &) = delete;
  IntegrationTestFixture(IntegrationTestFixture &&) = delete;
  IntegrationTestFixture &operator=(IntegrationTestFixture &&) = delete;

  void init_appcast()
  {
    std::ifstream finstaller("test-installer.exe", std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(finstaller)), std::istreambuf_iterator<char>());

    std::ifstream fappcast("appcast.xml");
    std::string appcast((std::istreambuf_iterator<char>(fappcast)), std::istreambuf_iterator<char>());

    const auto *key =
      "-----BEGIN PRIVATE KEY-----\n"
      "MC4CAQAwBQYDK2VwBCIEIGr4JHh7bcf/IBR+UGLPliWPMXe4cT9rPfyvaJCNLGgq\n"
      "-----END PRIVATE KEY-----\n";
    auto sig = sign(content, key);

    boost::replace_all(appcast, "$SIGNATURE", sig);
    boost::replace_all(appcast, "$LENGTH", std::to_string(content.length()));

    server.add("/appcast.xml", appcast);
    server.add("/installer.exe", content);
    server.run();
  }
  unfold::http::HttpServer server;
  std::shared_ptr<TestPlatform> platform;
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("test")};
};

BOOST_FIXTURE_TEST_SUITE(unfold_integration_test, IntegrationTestFixture)

BOOST_AUTO_TEST_CASE(upgrade_control_invalid_key)
{
  unfold::coro::IOContext io_context;
  UpgradeControl control(platform, io_context);

  auto rc = control.set_signature_verification_key("xxxxMCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=xxx");
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InvalidArgument);
}

// TODO: detect invalid cert
// BOOST_AUTO_TEST_CASE(upgrade_control_invalid_cert)
// {
//   unfold::coro::IOContext io_context;
//   UpgradeControl control(platform, io_context);

//   auto rc = control.set_certificate("cert");
//   BOOST_CHECK_EQUAL(rc.has_error(), true);
//   BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InvalidArgument);
// }

BOOST_AUTO_TEST_CASE(upgrade_control_check_alpha)
{
  unfold::coro::IOContext io_context;
  UpgradeControl control(platform, io_context);

  init_appcast();
  control.set_configuration_prefix("Software\\Unfold\\Test");

  auto rc = control.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control.set_certificate(cert);

  rc = control.set_signature_verification_key("MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_current_version("1.10.45");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_allowed_channels({"alpha"});
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  double last_progress = 0.0;
  std::optional<unfold::UpdateStage> last_stage;
  control.set_download_progress_callback([&last_stage, &last_progress](unfold::UpdateStage stage, auto progress) {
    if (stage == unfold::UpdateStage::DownloadInstaller)
      {
        BOOST_CHECK_GE(progress, last_progress);
        last_progress = progress;
      }

    if (!last_stage)
      {
        BOOST_CHECK_EQUAL(stage, unfold::UpdateStage::DownloadInstaller);
      }
    else if (*last_stage == unfold::UpdateStage::DownloadInstaller)
      {
        BOOST_CHECK(stage == unfold::UpdateStage::DownloadInstaller || stage == unfold::UpdateStage::VerifyInstaller);
      }
    else
      {
        BOOST_CHECK_EQUAL(stage, *last_stage + 1);
      }
    last_stage = stage;
  });

  std::optional<outcome::std_result<void>> status;
  control.set_update_status_callback([&](outcome::std_result<void> rc) {
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
    status = rc;
  });

  control.get_hooks()->hook_terminate() = []() { return false; };

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control.check_for_update();
          BOOST_CHECK_EQUAL(rc.has_error(), false);

          auto update_info = control.get_update_info();
          BOOST_CHECK_EQUAL(update_info->title, "Workrave");
          BOOST_CHECK_EQUAL(update_info->current_version, "1.10.45");
          BOOST_CHECK_EQUAL(update_info->version, "1.11.0-alpha.1");
          BOOST_CHECK_EQUAL(update_info->release_notes.size(), 4);
          BOOST_CHECK_EQUAL(update_info->release_notes.front().version, "1.11.0-alpha.1");

          std::filesystem::remove("installer.log");

          auto ri = co_await control.install_update();
          BOOST_CHECK_EQUAL(ri.has_error(), false);
          int tries = 100;
          bool found = false;
          do
            {
              found = std::filesystem::exists("installer.log");
              std::this_thread::sleep_for(std::chrono::milliseconds(50));
              tries--;
            }
          while (tries > 0 && !found);
          BOOST_CHECK(found);
          BOOST_CHECK_GE(100, last_progress);
          BOOST_CHECK_EQUAL(platform->is_terminated(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(status.has_value(), false);
  BOOST_CHECK_EQUAL(*last_stage, unfold::UpdateStage::RunInstaller);
}

BOOST_AUTO_TEST_CASE(upgrade_control_check_release)
{
  unfold::coro::IOContext io_context;
  UpgradeControl control(platform, io_context);

  init_appcast();
  control.set_configuration_prefix("Software\\Unfold\\Test");

  auto rc = control.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control.set_certificate(cert);

  rc = control.set_signature_verification_key("MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_current_version("1.10.45");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_allowed_channels({"release"});
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  double last_progress = 0.0;
  std::optional<unfold::UpdateStage> last_stage;
  control.set_download_progress_callback([&last_stage, &last_progress](unfold::UpdateStage stage, auto progress) {
    if (stage == unfold::UpdateStage::DownloadInstaller)
      {
        BOOST_CHECK_GE(progress, last_progress);
        last_progress = progress;
      }

    if (!last_stage)
      {
        BOOST_CHECK_EQUAL(stage, unfold::UpdateStage::DownloadInstaller);
      }
    else if (*last_stage == unfold::UpdateStage::DownloadInstaller)
      {
        BOOST_CHECK(stage == unfold::UpdateStage::DownloadInstaller || stage == unfold::UpdateStage::VerifyInstaller);
      }
    else
      {
        BOOST_CHECK_EQUAL(stage, *last_stage + 1);
      }
    last_stage = stage;
  });

  std::optional<outcome::std_result<void>> status;
  control.set_update_status_callback([&](outcome::std_result<void> rc) {
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
    status = rc;
  });

  control.get_hooks()->hook_terminate() = []() { return false; };

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control.check_for_update();
          BOOST_CHECK_EQUAL(rc.has_error(), false);

          auto update_info = control.get_update_info();
          BOOST_CHECK_EQUAL(update_info->title, "Workrave");
          BOOST_CHECK_EQUAL(update_info->current_version, "1.10.45");
          BOOST_CHECK_EQUAL(update_info->version, "1.10.49");
          BOOST_CHECK_EQUAL(update_info->release_notes.size(), 3);
          BOOST_CHECK_EQUAL(update_info->release_notes.front().version, "1.10.49");

          std::filesystem::remove("installer.log");

          auto ri = co_await control.install_update();
          BOOST_CHECK_EQUAL(ri.has_error(), false);
          int tries = 100;
          bool found = false;
          do
            {
              found = std::filesystem::exists("installer.log");
              std::this_thread::sleep_for(std::chrono::milliseconds(50));
              tries--;
            }
          while (tries > 0 && !found);
          BOOST_CHECK(found);
          BOOST_CHECK_GE(100, last_progress);
          BOOST_CHECK_EQUAL(platform->is_terminated(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(status.has_value(), false);
  BOOST_CHECK_EQUAL(*last_stage, unfold::UpdateStage::RunInstaller);
}

BOOST_AUTO_TEST_CASE(upgrade_last_upgrade_time)
{
  init_appcast();
  unfold::coro::IOContext io_context;
  UpgradeControl control(platform, io_context);

  control.set_configuration_prefix("Software\\Unfold\\Test");

  auto rc = control.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control.set_certificate(cert);
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_signature_verification_key("MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_current_version("1.10.45");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control.check_for_update();
          BOOST_CHECK_EQUAL(rc.has_error(), false);

          auto l1 = control.get_last_update_check_time();
          sleep(1);

          rc = co_await control.check_for_update();
          BOOST_CHECK_EQUAL(rc.has_error(), false);

          auto l2 = control.get_last_update_check_time();
          BOOST_CHECK_GE((*l2).time_since_epoch().count(), (*l1).time_since_epoch().count());
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
}

BOOST_AUTO_TEST_CASE(upgrade_control_periodic_check_later)
{
  init_appcast();

  unfold::coro::IOContext io_context;
  UpgradeControl control(platform, io_context);

  auto rc = control.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control.set_certificate(cert);

  rc = control.set_signature_verification_key("MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_current_version("1.10.45");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control.reset_skip_version();
  control.set_periodic_update_check_interval(std::chrono::seconds{1});
  control.set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    co_return unfold::UpdateResponse::Later;
  });

  std::optional<outcome::std_result<void>> status;
  control.set_update_status_callback([&](outcome::std_result<void> rc) {
    status = rc;
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
  });

  control.set_periodic_update_check_enabled(true);

  io_context.wait();
  BOOST_CHECK_EQUAL(status.has_value(), false);
}

BOOST_AUTO_TEST_CASE(upgrade_control_periodic_check_skip)
{
  init_appcast();

  unfold::coro::IOContext io_context;
  UpgradeControl control(platform, io_context);

  auto rc = control.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control.set_certificate(cert);

  rc = control.set_signature_verification_key("MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_current_version("1.10.45");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control.reset_skip_version();
  control.set_periodic_update_check_interval(std::chrono::seconds{1});
  control.set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    co_return unfold::UpdateResponse::Skip;
  });

  std::optional<outcome::std_result<void>> status;
  control.set_update_status_callback([&](outcome::std_result<void> rc) {
    status = rc;
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
  });

  control.set_periodic_update_check_enabled(true);

  io_context.wait();

  BOOST_CHECK_EQUAL(control.get_skip_version(), "1.11.0-alpha.1");
  BOOST_CHECK_EQUAL(status.has_value(), false);
}

BOOST_AUTO_TEST_CASE(upgrade_control_periodic_check_install_now)
{
  init_appcast();

  unfold::coro::IOContext io_context;
  UpgradeControl control(platform, io_context);

  auto rc = control.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control.set_certificate(cert);

  rc = control.set_signature_verification_key("MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_current_version("1.10.45");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control.reset_skip_version();
  control.set_periodic_update_check_interval(std::chrono::seconds{1});
  control.set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    control.set_periodic_update_check_enabled(false);
    co_return unfold::UpdateResponse::Install;
  });
  control.set_download_progress_callback([&](unfold::UpdateStage stage, auto progress) {
    if (stage == unfold::UpdateStage::RunInstaller)
      {
        io_context.stop();
      }
  });

  std::optional<outcome::std_result<void>> status;
  control.set_update_status_callback([&](outcome::std_result<void> rc) {
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
    status = rc;
  });

  control.set_periodic_update_check_enabled(true);
  std::filesystem::remove("installer.log");

  io_context.wait();
  int tries = 100;
  bool found = false;
  do
    {
      found = std::filesystem::exists("installer.log");
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      tries--;
    }
  while (tries > 0 && !found);
  BOOST_CHECK(found);
}

BOOST_AUTO_TEST_SUITE_END()
