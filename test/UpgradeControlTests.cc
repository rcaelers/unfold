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

#include <fstream>
#include <algorithm>

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/outcome/success_failure.hpp>
#include <gmock/gmock-cardinalities.h>
#include <memory>
#include <optional>
#include <spdlog/spdlog.h>

#include "UnfoldInternalErrors.hh"
#include "unfold/Unfold.hh"
#include "unfold/UnfoldErrors.hh"

#include "TestPlatform.hh"
#include "UpgradeControl.hh"
#include "SettingsStorageMock.hh"
#include "SignatureVerifierMock.hh"
#include "CheckerMock.hh"
#include "InstallerMock.hh"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;

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

struct MockedTestFixture
{
  ~MockedTestFixture() = default;

  MockedTestFixture(const MockedTestFixture &) = delete;
  MockedTestFixture &operator=(const MockedTestFixture &) = delete;
  MockedTestFixture(MockedTestFixture &&) = delete;
  MockedTestFixture &operator=(MockedTestFixture &&) = delete;

  MockedTestFixture()
  {
    platform = std::make_shared<TestPlatform>();

    http = std::make_shared<unfold::http::HttpClient>();
    verifier = std::make_shared<SignatureVerifierMock>();
    storage = std::make_shared<SettingsStorageMock>();
    checker = std::make_shared<CheckerMock>();
    installer = std::make_shared<InstallerMock>();

    EXPECT_CALL(*storage, get_value("Priority", SettingType::Int32)).Times(1).WillOnce(Return(outcome::success(0)));
    EXPECT_CALL(*storage, set_value("Priority", _)).Times(1).WillRepeatedly(Return(outcome::success()));
    ;

    control = std::make_shared<UpgradeControl>(platform, http, verifier, storage, installer, checker, io_context);
  }

  unfold::coro::IOContext io_context;
  std::shared_ptr<unfold::http::HttpClient> http;
  std::shared_ptr<SignatureVerifierMock> verifier;
  std::shared_ptr<SettingsStorageMock> storage;
  std::shared_ptr<InstallerMock> installer;
  std::shared_ptr<CheckerMock> checker;
  std::shared_ptr<UpgradeControl> control;
  std::shared_ptr<TestPlatform> platform;
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("test")};
};

template<>
struct unfold::utils::enum_traits<unfold::UpdateStage>
{
  static constexpr auto min = unfold::UpdateStage::DownloadInstaller;
  static constexpr auto max = unfold::UpdateStage::RunInstaller;
  static constexpr auto linear = true;

  static constexpr std::array<std::pair<std::string_view, unfold::UpdateStage>, 3> names{
    {{"Download", unfold::UpdateStage::DownloadInstaller},
     {"Run", unfold::UpdateStage::RunInstaller},
     {"Verify", unfold::UpdateStage::VerifyInstaller}}};
};

namespace unfold
{
  inline std::ostream &operator<<(std::ostream &os, unfold::UpdateStage e)
  {
    os << unfold::utils::enum_to_string(e);
    return os;
  }
} // namespace unfold

BOOST_FIXTURE_TEST_SUITE(unfold_upgrade_control_test, MockedTestFixture)

BOOST_AUTO_TEST_CASE(upgrade_control_periodic_check_later)
{
  EXPECT_CALL(*checker, set_appcast("https://127.0.0.1:1337/appcast.xml")).Times(1).WillOnce(Return(outcome::success()));

  auto rc = control->set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control->set_certificate(cert);

  EXPECT_CALL(*verifier,
              set_key(unfold::crypto::SignatureAlgorithmType::ECDSA,
                      "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM="))
    .Times(1)
    .WillOnce(Return(outcome::success()));

  rc = control->set_signature_verification_key("MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  EXPECT_CALL(*checker, set_current_version("1.10.45")).Times(1).WillOnce(Return(outcome::success()));

  rc = control->set_current_version("1.10.45");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  EXPECT_CALL(*storage, set_prefix("some\\prefix")).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));
  EXPECT_CALL(*storage, set_prefix("some\\wrong\\prefix"))
    .Times(AtLeast(1))
    .WillRepeatedly(Return(outcome::failure(UnfoldInternalErrc::InternalError)));
  control->set_configuration_prefix("some\\prefix");
  control->set_configuration_prefix("some\\wrong\\prefix");

  EXPECT_CALL(*storage, get_value("LastUpdateCheckTime", SettingType::Int64))
    .Times(AtLeast(1))
    .WillRepeatedly(Return(outcome::success(32LL)));

  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));
  EXPECT_CALL(*storage, get_value("SkipVersion", SettingType::String))
    .Times(AtLeast(1))
    .WillRepeatedly(Return(outcome::success("")));
  EXPECT_CALL(*storage, set_value("SkipVersion", SettingValue{""})).Times(2).WillRepeatedly(Return(outcome::success()));

  control->reset_skip_version();
  control->set_periodic_update_check_interval(std::chrono::seconds{1});
  control->set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    co_return unfold::UpdateResponse::Later;
  });

  EXPECT_CALL(*checker, check_for_update())
    .Times(AtLeast(1))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<bool>> { co_return outcome::success(true); }));

  EXPECT_CALL(*checker, get_update_info())
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([]() -> std::shared_ptr<unfold::UpdateInfo> {
      auto info = std::make_shared<unfold::UpdateInfo>();
      info->current_version = "1.10.45";
      info->version = "1.11.0-alpha.1";
      info->title = "Workrave";
      auto r = unfold::UpdateReleaseNotes{"1.11.0-alpha.1", "x", "x"};
      info->release_notes.push_back(r);
      return info;
    }));
  control->set_periodic_update_check_enabled(true);

  io_context.wait();
}

BOOST_AUTO_TEST_CASE(upgrade_control_checker_failed)
{
  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  bool available{false};
  control->set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    co_return unfold::UpdateResponse::Later;
  });

  std::optional<outcome::std_result<void>> status;
  control->set_update_status_callback([&](outcome::std_result<void> rc) {
    status = rc;
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
  });

  EXPECT_CALL(*checker, check_for_update())
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<bool>> {
      co_return outcome::failure(unfold::UnfoldErrc::AppcastDownloadFailed);
    }));

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control->check_for_update_and_notify();
          BOOST_CHECK_EQUAL(rc.has_error(), true);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(available, false);
  BOOST_CHECK_EQUAL(status.has_value(), true);
  BOOST_CHECK_EQUAL(status->has_error(), true);
  BOOST_CHECK_EQUAL(status->error(), unfold::UnfoldErrc::AppcastDownloadFailed);
}

BOOST_AUTO_TEST_CASE(upgrade_control_no_upgrade_available)
{
  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  bool available{false};
  control->set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    available = true;
    co_return unfold::UpdateResponse::Later;
  });

  std::optional<outcome::std_result<void>> status;
  control->set_update_status_callback([&](outcome::std_result<void> rc) {
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
    status = rc;
  });

  EXPECT_CALL(*checker, check_for_update())
    .Times(AtLeast(1))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<bool>> { co_return outcome::success(false); }));

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control->check_for_update_and_notify();
          BOOST_CHECK_EQUAL(rc.has_error(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(available, false);
  BOOST_CHECK_EQUAL(status.has_value(), false);
}

BOOST_AUTO_TEST_CASE(upgrade_control_no_upgrade_info)
{
  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  bool available{false};
  control->set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    available = true;
    co_return unfold::UpdateResponse::Later;
  });

  std::optional<outcome::std_result<void>> status;
  control->set_update_status_callback([&](outcome::std_result<void> rc) {
    status = rc;
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
  });

  EXPECT_CALL(*checker, check_for_update())
    .Times(AtLeast(1))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<bool>> { co_return outcome::success(true); }));

  EXPECT_CALL(*checker, get_update_info()).Times(1).WillRepeatedly(Return(std::shared_ptr<unfold::UpdateInfo>{}));

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control->check_for_update_and_notify();
          BOOST_CHECK_EQUAL(rc.has_error(), true);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(available, false);
  BOOST_CHECK_EQUAL(status.has_value(), true);
  BOOST_CHECK_EQUAL(status->has_error(), true);
  BOOST_CHECK_EQUAL(status->error(), unfold::UnfoldErrc::InternalError);
}

BOOST_AUTO_TEST_CASE(upgrade_control_skip_version)
{
  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  bool available{false};
  control->set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    available = true;
    co_return unfold::UpdateResponse::Later;
  });

  std::optional<outcome::std_result<void>> status;
  control->set_update_status_callback([&](outcome::std_result<void> rc) {
    status = rc;
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
  });

  EXPECT_CALL(*checker, check_for_update())
    .Times(AtLeast(1))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<bool>> { co_return outcome::success(true); }));

  EXPECT_CALL(*storage, get_value("SkipVersion", SettingType::String))
    .Times(AtLeast(1))
    .WillRepeatedly(Return(outcome::success("1.11.0-alpha.1")));

  EXPECT_CALL(*checker, get_update_info())
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([]() -> std::shared_ptr<unfold::UpdateInfo> {
      auto info = std::make_shared<unfold::UpdateInfo>();
      info->current_version = "1.10.45";
      info->version = "1.11.0-alpha.1";
      info->title = "Workrave";
      auto r = unfold::UpdateReleaseNotes{"1.11.0-alpha.1", "x", "x"};
      info->release_notes.push_back(r);
      return info;
    }));

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control->check_for_update_and_notify(false);
          BOOST_CHECK_EQUAL(rc.has_error(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(available, false);
  BOOST_CHECK_EQUAL(status.has_value(), false);
}

BOOST_AUTO_TEST_CASE(upgrade_control_skip_version_ignore)
{
  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  bool available{false};
  control->set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    available = true;
    co_return unfold::UpdateResponse::Later;
  });

  std::optional<outcome::std_result<void>> status;
  control->set_update_status_callback([&](outcome::std_result<void> rc) {
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
    status = rc;
  });

  EXPECT_CALL(*storage, set_value("SkipVersion", SettingValue{""})).Times(1).WillOnce(Return(outcome::success()));

  EXPECT_CALL(*checker, check_for_update())
    .Times(AtLeast(1))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<bool>> { co_return outcome::success(true); }));

  EXPECT_CALL(*checker, get_update_info())
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([]() -> std::shared_ptr<unfold::UpdateInfo> {
      auto info = std::make_shared<unfold::UpdateInfo>();
      info->current_version = "1.10.45";
      info->version = "1.11.0-alpha.1";
      info->title = "Workrave";
      auto r = unfold::UpdateReleaseNotes{"1.11.0-alpha.1", "x", "x"};
      info->release_notes.push_back(r);
      return info;
    }));

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control->check_for_update_and_notify();
          BOOST_CHECK_EQUAL(rc.has_error(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(available, true);
  BOOST_CHECK_EQUAL(status.has_value(), false);
}

BOOST_AUTO_TEST_CASE(upgrade_control_no_callback)
{
  std::optional<outcome::std_result<void>> status;
  control->set_update_status_callback([&](outcome::std_result<void> rc) {
    status = rc;
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
  });

  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  EXPECT_CALL(*checker, check_for_update())
    .Times(AtLeast(1))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<bool>> { co_return outcome::success(true); }));

  EXPECT_CALL(*checker, get_update_info())
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([]() -> std::shared_ptr<unfold::UpdateInfo> {
      auto info = std::make_shared<unfold::UpdateInfo>();
      info->current_version = "1.10.45";
      info->version = "1.11.0-alpha.1";
      info->title = "Workrave";
      auto r = unfold::UpdateReleaseNotes{"1.11.0-alpha.1", "x", "x"};
      info->release_notes.push_back(r);
      return info;
    }));

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control->check_for_update_and_notify();
          BOOST_CHECK_EQUAL(rc.has_error(), true);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(status.has_value(), true);
  BOOST_CHECK_EQUAL(status->has_error(), true);
  BOOST_CHECK_EQUAL(status->error(), unfold::UnfoldErrc::InvalidArgument);
}

BOOST_AUTO_TEST_CASE(upgrade_control_callback_later)
{
  EXPECT_CALL(*storage, set_value("SkipVersion", SettingValue{""})).Times(1).WillOnce(Return(outcome::success()));
  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  bool available{false};
  control->set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    available = true;
    co_return unfold::UpdateResponse::Later;
  });

  std::optional<outcome::std_result<void>> status;
  control->set_update_status_callback([&](outcome::std_result<void> rc) {
    status = rc;
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
  });

  EXPECT_CALL(*checker, check_for_update())
    .Times(AtLeast(1))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<bool>> { co_return outcome::success(true); }));

  EXPECT_CALL(*checker, get_update_info())
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([]() -> std::shared_ptr<unfold::UpdateInfo> {
      auto info = std::make_shared<unfold::UpdateInfo>();
      info->current_version = "1.10.45";
      info->version = "1.11.0-alpha.1";
      info->title = "Workrave";
      auto r = unfold::UpdateReleaseNotes{"1.11.0-alpha.1", "x", "x"};
      info->release_notes.push_back(r);
      return info;
    }));

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control->check_for_update_and_notify();
          BOOST_CHECK_EQUAL(rc.has_error(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(available, true);
}

BOOST_AUTO_TEST_CASE(upgrade_control_callback_skip)
{
  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  bool available{false};
  control->set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    available = true;
    co_return unfold::UpdateResponse::Skip;
  });

  std::optional<outcome::std_result<void>> status;
  control->set_update_status_callback([&](outcome::std_result<void> rc) {
    status = rc;
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
  });

  EXPECT_CALL(*checker, check_for_update())
    .Times(AtLeast(1))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<bool>> { co_return outcome::success(true); }));

  EXPECT_CALL(*storage, get_value("SkipVersion", SettingType::String))
    .Times(AtLeast(1))
    .WillRepeatedly(Return(outcome::success("1.11.0-alpha.0")));

  EXPECT_CALL(*storage, set_value("SkipVersion", SettingValue{"1.11.0-alpha.1"})).Times(1).WillOnce(Return(outcome::success()));

  EXPECT_CALL(*checker, get_update_info())
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([]() -> std::shared_ptr<unfold::UpdateInfo> {
      auto info = std::make_shared<unfold::UpdateInfo>();
      info->current_version = "1.10.45";
      info->version = "1.11.0-alpha.1";
      info->title = "Workrave";
      auto r = unfold::UpdateReleaseNotes{"1.11.0-alpha.1", "x", "x"};
      info->release_notes.push_back(r);
      return info;
    }));

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control->check_for_update_and_notify(false);
          BOOST_CHECK_EQUAL(rc.has_error(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(available, true);
  BOOST_CHECK_EQUAL(status.has_value(), false);
}

BOOST_AUTO_TEST_CASE(upgrade_control_callback_install)
{
  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  bool available{false};
  control->set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    available = true;
    co_return unfold::UpdateResponse::Install;
  });

  std::optional<outcome::std_result<void>> status;
  control->set_update_status_callback([&](outcome::std_result<void> rc) {
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
    status = rc;
  });

  EXPECT_CALL(*checker, check_for_update())
    .Times(AtLeast(1))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<bool>> { co_return outcome::success(true); }));

  EXPECT_CALL(*checker, get_update_info())
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([]() -> std::shared_ptr<unfold::UpdateInfo> {
      auto info = std::make_shared<unfold::UpdateInfo>();
      info->current_version = "1.10.45";
      info->version = "1.11.0-alpha.1";
      info->title = "Workrave";
      auto r = unfold::UpdateReleaseNotes{"1.11.0-alpha.1", "x", "x"};
      info->release_notes.push_back(r);
      return info;
    }));

  auto item = std::make_shared<AppcastItem>();
  EXPECT_CALL(*checker, get_selected_update())
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([item]() -> std::shared_ptr<AppcastItem> { return item; }));

  EXPECT_CALL(*installer, install(item))
    .Times(AtLeast(1))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control->check_for_update_and_notify();
          BOOST_CHECK_EQUAL(rc.has_error(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(available, true);
  BOOST_CHECK_EQUAL(status.has_value(), false);
}

BOOST_AUTO_TEST_CASE(upgrade_control_callback_install_failed)
{
  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  bool available{false};
  control->set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    available = true;
    co_return unfold::UpdateResponse::Install;
  });

  std::optional<outcome::std_result<void>> status;
  control->set_update_status_callback([&](outcome::std_result<void> rc) {
    status = rc;
    if (rc.has_error())
      {
        spdlog::info("Update status {}", rc.error().message());
      }
  });

  EXPECT_CALL(*checker, check_for_update())
    .Times(AtLeast(1))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<bool>> { co_return outcome::success(true); }));

  EXPECT_CALL(*checker, get_update_info())
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([]() -> std::shared_ptr<unfold::UpdateInfo> {
      auto info = std::make_shared<unfold::UpdateInfo>();
      info->current_version = "1.10.45";
      info->version = "1.11.0-alpha.1";
      info->title = "Workrave";
      auto r = unfold::UpdateReleaseNotes{"1.11.0-alpha.1", "x", "x"};
      info->release_notes.push_back(r);
      return info;
    }));

  auto item = std::make_shared<AppcastItem>();
  EXPECT_CALL(*checker, get_selected_update())
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([item]() -> std::shared_ptr<AppcastItem> { return item; }));

  EXPECT_CALL(*installer, install(item))
    .Times(AtLeast(1))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> {
      co_return outcome::failure(unfold::UnfoldErrc::InternalError);
    }));

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control->check_for_update_and_notify();
          BOOST_CHECK_EQUAL(rc.has_error(), true);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  BOOST_CHECK_EQUAL(available, true);
  BOOST_CHECK_EQUAL(status.has_value(), true);
  BOOST_CHECK_EQUAL(status->has_error(), true);
  BOOST_CHECK_EQUAL(status->error(), unfold::UnfoldErrc::InternalError);
}

BOOST_AUTO_TEST_CASE(upgrade_control_proxy)
{
  control->set_proxy(unfold::ProxyType::None);
  BOOST_CHECK_EQUAL(http->options().get_proxy(), unfold::http::Options::ProxyType::None);
  control->set_proxy(unfold::ProxyType::System);
  BOOST_CHECK_EQUAL(http->options().get_proxy(), unfold::http::Options::ProxyType::System);
  control->set_proxy(unfold::ProxyType::Custom);
  BOOST_CHECK_EQUAL(http->options().get_proxy(), unfold::http::Options::ProxyType::Custom);
  control->set_custom_proxy("http://proxy:8080");
  BOOST_CHECK_EQUAL(http->options().get_custom_proxy(), "http://proxy:8080");
  control->set_proxy(unfold::ProxyType::None);
  BOOST_CHECK_EQUAL(http->options().get_proxy(), unfold::http::Options::ProxyType::None);
}

BOOST_AUTO_TEST_CASE(upgrade_control_priority)
{
  EXPECT_CALL(*storage, get_value("Priority", SettingType::Int32)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success(10)));

  BOOST_CHECK_EQUAL(control->get_priority(), 10);
  auto ret = control->set_priority(5);
  BOOST_CHECK_EQUAL(ret.has_error(), false);
  BOOST_CHECK_EQUAL(control->get_priority(), 5);
  control->unset_priority();
  BOOST_CHECK_EQUAL(control->get_priority(), 10);
  ret = control->set_priority(101);
  BOOST_CHECK_EQUAL(ret.has_error(), true);
  ret = control->set_priority(0);
  BOOST_CHECK_EQUAL(ret.has_error(), true);
  ret = control->set_priority(-1);
  BOOST_CHECK_EQUAL(ret.has_error(), true);
}

BOOST_AUTO_TEST_SUITE_END()
