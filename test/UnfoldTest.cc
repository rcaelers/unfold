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

#include "unfold/Unfold.hh"
#include "unfold/UnfoldErrors.hh"
#include <boost/outcome/success_failure.hpp>
#include <filesystem>
#include <memory>
#include <string>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#if SPDLOG_VERSION >= 10600
#  include <spdlog/pattern_formatter.h>
#endif
#if SPDLOG_VERSION >= 10801
#  include <spdlog/cfg/env.h>
#endif
#include <spdlog/fmt/ostr.h>

#include "http/HttpServer.hh"
#include "utils/Logging.hh"
#include "utils/IOContext.hh"

#include "AppCast.hh"
#include "TestPlatform.hh"
#include "UpgradeControl.hh"

#if defined(_WIN32)
#  include "windows/WindowsSettingsStorage.hh"
#endif

#include "SignatureVerifierMock.hh"

#define BOOST_TEST_MODULE "unfold"
#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

using namespace unfold::utils;
using ::testing::_;
using ::testing::AtLeast;
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

struct GlobalFixture
{
  GlobalFixture() = default;
  ~GlobalFixture() = default;

  GlobalFixture(const GlobalFixture &) = delete;
  GlobalFixture &operator=(const GlobalFixture &) = delete;
  GlobalFixture(GlobalFixture &&) = delete;
  GlobalFixture &operator=(GlobalFixture &&) = delete;

  void setup()
  {
    const auto *log_file = "unfold-test.log";

    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file, false);
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    auto logger{std::make_shared<spdlog::logger>("unfold", std::initializer_list<spdlog::sink_ptr>{file_sink, console_sink})};
    logger->flush_on(spdlog::level::critical);
    spdlog::set_default_logger(logger);

    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%-5l%$] %v");

#if SPDLOG_VERSION >= 10801
    spdlog::cfg::load_env_levels();
#endif
  }

private:
};

struct Fixture
{
  Fixture() = default;
  ~Fixture() = default;

  Fixture(const Fixture &) = delete;
  Fixture &operator=(const Fixture &) = delete;
  Fixture(Fixture &&) = delete;
  Fixture &operator=(Fixture &&) = delete;

private:
  std::shared_ptr<spdlog::logger> logger{Logging::create("test")};
};

BOOST_TEST_GLOBAL_FIXTURE(GlobalFixture);

BOOST_FIXTURE_TEST_SUITE(unfold_test, Fixture)

BOOST_AUTO_TEST_CASE(appcast_load_from_string)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string appcast_str =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\"\n"
    "    xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Workrave Test Appcast</title>\n"
    "        <description>Most recent updates to Workrave Test</description>\n"
    "        <language>en</language>\n"
    "        <link>https://workrave.org/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>1.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure url=\"http://localhost:1337/v2.zip\" sparkle:edSignature=\"xx\" length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(appcast_str);

  BOOST_CHECK_EQUAL(appcast->title, "Workrave Test Appcast");
  BOOST_CHECK_EQUAL(appcast->description, "Most recent updates to Workrave Test");
  BOOST_CHECK_EQUAL(appcast->language, "en");
  BOOST_CHECK_EQUAL(appcast->link, "https://workrave.org/");

  BOOST_CHECK_EQUAL(appcast->items.size(), 1);

  BOOST_CHECK_EQUAL(appcast->items[0]->channel, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->title, "Version 1.0");
  BOOST_CHECK_EQUAL(appcast->items[0]->link, "https://workrave.org");
  BOOST_CHECK_EQUAL(appcast->items[0]->version, "1.0");
  BOOST_CHECK_EQUAL(appcast->items[0]->short_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->description, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->release_notes_link, "https://workrave.org/v1.html");
  BOOST_CHECK_EQUAL(appcast->items[0]->publication_date, "Sun Apr 17 19:30:14 CEST 2022");
  BOOST_CHECK_EQUAL(appcast->items[0]->minimum_system_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->minimum_auto_update_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->ignore_skipped_upgrades_below_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->critical_update, false);
  BOOST_CHECK_EQUAL(appcast->items[0]->critical_update_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->phased_rollout_interval, 0);
}

BOOST_AUTO_TEST_CASE(appcast_load_from_file)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_file("okappcast.xml");

  BOOST_CHECK_EQUAL(appcast->title, "Workrave Test Appcast");
  BOOST_CHECK_EQUAL(appcast->description, "Most recent updates to Workrave Test");
  BOOST_CHECK_EQUAL(appcast->language, "en");
  BOOST_CHECK_EQUAL(appcast->link, "https://workrave.org/");

  BOOST_CHECK_EQUAL(appcast->items.size(), 2);

  BOOST_CHECK_EQUAL(appcast->items[0]->channel, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->title, "Version 1.0");
  BOOST_CHECK_EQUAL(appcast->items[0]->link, "https://workrave.org");
  BOOST_CHECK_EQUAL(appcast->items[0]->version, "1.0");
  BOOST_CHECK_EQUAL(appcast->items[0]->short_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->description, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->release_notes_link, "https://workrave.org/v1.html");
  BOOST_CHECK_EQUAL(appcast->items[0]->publication_date, "Sun Apr 17 19:30:14 CEST 2022");
  BOOST_CHECK_EQUAL(appcast->items[0]->minimum_system_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->minimum_auto_update_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->ignore_skipped_upgrades_below_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->critical_update, false);
  BOOST_CHECK_EQUAL(appcast->items[0]->critical_update_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->phased_rollout_interval, 0);

  BOOST_CHECK_EQUAL(appcast->items[1]->channel, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->title, "Version 2.0");
  BOOST_CHECK_EQUAL(appcast->items[1]->link, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->version, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->short_version, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->description, "Version 2 update");
  BOOST_CHECK_EQUAL(appcast->items[1]->release_notes_link, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->publication_date, "Sun Apr 17 19:30:14 CEST 2022");
  BOOST_CHECK_EQUAL(appcast->items[1]->minimum_system_version, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->minimum_auto_update_version, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->ignore_skipped_upgrades_below_version, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->critical_update, true);
  BOOST_CHECK_EQUAL(appcast->items[1]->critical_update_version, "1.5");
  BOOST_CHECK_EQUAL(appcast->items[1]->phased_rollout_interval, 0);
}

BOOST_AUTO_TEST_CASE(appcast_load_invalid_from_string)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string appcast_str = "Foo\n";

  auto appcast = reader->load_from_string(appcast_str);
  BOOST_CHECK_EQUAL(appcast.get(), nullptr);
}

BOOST_AUTO_TEST_CASE(appcast_load_invalid_from_file)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_file("invalidappcast.xml");
  BOOST_CHECK_EQUAL(appcast.get(), nullptr);
}

#if defined(_WIN32)

BOOST_AUTO_TEST_CASE(Windows_settings_string)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  rc = storage.remove_key("foo");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  auto s = storage.get_value("foo", SettingType::String);
  BOOST_CHECK_EQUAL(s.has_value(), false);
  rc = storage.set_value("foo", "bar");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::String);
  BOOST_CHECK_EQUAL(s.has_value(), true);
  BOOST_CHECK_EQUAL(std::get<std::string>(s.value()), "bar");
  BOOST_CHECK_EQUAL(SettingValueToType(s.value()), SettingType::String);
}

BOOST_AUTO_TEST_CASE(Windows_settings_int64)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  rc = storage.remove_key("foo");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  auto s = storage.get_value("foo", SettingType::Int64);
  BOOST_CHECK_EQUAL(s.has_value(), false);
  rc = storage.set_value("foo", 42LL);
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Int64);
  BOOST_CHECK_EQUAL(s.has_value(), true);
  BOOST_CHECK_EQUAL(std::get<int64_t>(s.value()), 42LL);
  BOOST_CHECK_EQUAL(SettingValueToType(s.value()), SettingType::Int64);
}

BOOST_AUTO_TEST_CASE(Windows_settings_int32)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  rc = storage.remove_key("foo");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  auto s = storage.get_value("foo", SettingType::Int32);
  BOOST_CHECK_EQUAL(s.has_value(), false);
  rc = storage.set_value("foo", 43);
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Int32);
  BOOST_CHECK_EQUAL(s.has_value(), true);
  BOOST_CHECK_EQUAL(std::get<int32_t>(s.value()), 43);
  BOOST_CHECK_EQUAL(SettingValueToType(s.value()), SettingType::Int32);
}

BOOST_AUTO_TEST_CASE(Windows_settings_bool)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  rc = storage.remove_key("foo");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  auto s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_value(), false);
  rc = storage.set_value("foo", true);
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_value(), true);
  BOOST_CHECK_EQUAL(std::get<bool>(s.value()), true);
  rc = storage.set_value("foo", false);
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_value(), true);
  BOOST_CHECK_EQUAL(std::get<bool>(s.value()), false);
  BOOST_CHECK_EQUAL(SettingValueToType(s.value()), SettingType::Boolean);
}

BOOST_AUTO_TEST_CASE(Windows_settings_remove)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  rc = storage.remove_key("foo");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  rc = storage.remove_key("\n");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
}

BOOST_AUTO_TEST_CASE(Windows_settings_invalid_subkey)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("\\\\");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  auto s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value("foo", SettingType::Int32);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value("foo", SettingType::Int64);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value("foo", SettingType::String);
  BOOST_CHECK_EQUAL(s.has_error(), true);

  rc = storage.remove_key("foo");
  BOOST_CHECK_EQUAL(rc.has_error(), true);

  rc = storage.set_value("foo", true);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value("foo", false);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value("foo", "bar");
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value("foo", 42);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value("foo", 42LL);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
}

namespace
{
  auto very_long_string = std::string(20 * 1024, 'a');
}

BOOST_AUTO_TEST_CASE(Windows_settings_get_invalid_key)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  auto s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::String);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::Int32);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::Int64);
  BOOST_CHECK_EQUAL(s.has_error(), true);

  rc = storage.remove_key(very_long_string);
  BOOST_CHECK_EQUAL(rc.has_error(), false); // Windows return "no such key"
}

BOOST_AUTO_TEST_CASE(Windows_settings_set_invalid_key)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  rc = storage.set_value(very_long_string, true);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value(very_long_string, false);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value(very_long_string, "bar");
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value(very_long_string, 42);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value(very_long_string, 42LL);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
}

#endif

BOOST_AUTO_TEST_CASE(checker_appcast_not_found)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  Checker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcastxxx.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = checker.set_current_version("1.12.0");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_updates();
          BOOST_CHECK_EQUAL(check_result.has_error(), true);
          BOOST_CHECK_EQUAL(check_result.error(), unfold::UnfoldErrc::AppcastDownloadFailed);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(checker_invalid_host)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  Checker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://300.0.0.1.2:1337/appcastxxx.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = checker.set_current_version("1.12.0");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_updates();
          BOOST_CHECK_EQUAL(check_result.has_error(), true);
          BOOST_CHECK_EQUAL(check_result.error(), unfold::UnfoldErrc::AppcastDownloadFailed);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(checker_invalid_version)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  Checker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_current_version("1.12.0.1.2");
  BOOST_CHECK_EQUAL(rc.has_error(), true);
}

BOOST_AUTO_TEST_CASE(checker_invalid_appcast)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "invalidappcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  Checker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_updates();
          BOOST_CHECK_EQUAL(check_result.has_error(), true);
          BOOST_CHECK_EQUAL(check_result.error(), unfold::UnfoldErrc::InvalidAppcast);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(checker_empty_appcast)
{
  unfold::http::HttpServer server;
  server.add("/appcast.xml", "");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  Checker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_updates();
          BOOST_CHECK_EQUAL(check_result.has_error(), true);
          BOOST_CHECK_EQUAL(check_result.error(), unfold::UnfoldErrc::InvalidAppcast);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(checker_invalid_items_in_appcast)
{
  std::string appcast_str =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\"\n"
    "    xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Workrave Test Appcast</title>\n"
    "        <description>Most recent updates to Workrave Test</description>\n"
    "        <language>en</language>\n"
    "        <link>https://workrave.org/</link>\n"
    "        <item>\n"
    "            <title>Version 2.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>2.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v2.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure os=\"windows\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8192\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure os=\"windows\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8192\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "        <item>\n"
    "            <title>Version 3.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>3.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v2.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure os=\"macos\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8192\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "        <item>\n"
    "            <title>Version 5.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>5.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v2.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <sparkle:minimumSystemVersion>11.0.0</sparkle:minimumSystemVersion>\n"
    "            <enclosure os=\"windows\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8192\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "        <item>\n"
    "            <title>Version 4.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>4.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v2.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <sparkle:minimumSystemVersion>6.0.0</sparkle:minimumSystemVersion>\n"
    "            <enclosure os=\"windows\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8192\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  unfold::http::HttpServer server;
  server.add("/appcast.xml", appcast_str);
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  Checker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = checker.set_current_version("1.0.0");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_updates();
          BOOST_CHECK_EQUAL(check_result.has_error(), false);
          BOOST_CHECK_EQUAL(check_result.value(), true);

          auto appcast = checker.get_selected_update();
          BOOST_CHECK_EQUAL(appcast->version, "4.0.0");
          auto info = checker.get_update_info();
          BOOST_CHECK_EQUAL(info->title, "Workrave Test Appcast");
          BOOST_CHECK_EQUAL(info->current_version, "1.0.0");
          BOOST_CHECK_EQUAL(info->version, "4.0.0");
          BOOST_CHECK_EQUAL(info->release_notes.size(), 1);
          BOOST_CHECK_EQUAL(info->release_notes.front().version, "4.0.0");
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(checker_no_upgrade)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  Checker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = checker.set_current_version("1.12.0");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_updates();
          BOOST_CHECK_EQUAL(check_result.has_error(), false);
          BOOST_CHECK_EQUAL(check_result.value(), false);

          auto appcast = checker.get_selected_update();
          BOOST_CHECK_EQUAL(appcast.get(), nullptr);
          auto info = checker.get_update_info();
          BOOST_CHECK_EQUAL(info.get(), nullptr);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(checker_has_upgrade)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  Checker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_updates();
          BOOST_CHECK_EQUAL(check_result.has_error(), false);
          BOOST_CHECK_EQUAL(check_result.value(), true);

          auto appcast = checker.get_selected_update();
          BOOST_CHECK_EQUAL(appcast->version, "1.11.0-alpha.1");
          BOOST_CHECK_EQUAL(appcast->publication_date, "Sun, 27 Feb 2022 11:02:33 +0100");
          BOOST_CHECK_EQUAL(appcast->title, "Workrave 1.11.0-alpha.1");
          auto info = checker.get_update_info();
          BOOST_CHECK_EQUAL(info->title, "Workrave");
          BOOST_CHECK_EQUAL(info->current_version, "1.10.48");
          BOOST_CHECK_EQUAL(info->version, "1.11.0-alpha.1");
          BOOST_CHECK_EQUAL(info->release_notes.size(), 2);
          BOOST_CHECK_EQUAL(info->release_notes.front().version, "1.11.0-alpha.1");
          BOOST_CHECK_EQUAL(info->release_notes.front().date, "Sun, 27 Feb 2022 11:02:33 +0100");
          BOOST_CHECK_EQUAL(info->release_notes.back().version, "1.10.49");
          BOOST_CHECK_EQUAL(info->release_notes.back().date, "Wed, 05 Jan 2022 03:05:19 +0100");
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(installer_missing_url)
{
  std::string appcast_str =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\"\n"
    "    xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Workrave Test Appcast</title>\n"
    "        <description>Most recent updates to Workrave Test</description>\n"
    "        <language>en</language>\n"
    "        <link>https://workrave.org/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>1.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8192\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_string(appcast_str);

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  auto verifier = std::make_shared<SignatureVerifierMock>();

  Installer installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          BOOST_CHECK_EQUAL(rc.has_error(), true);
          BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InstallerDownloadFailed);
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

BOOST_AUTO_TEST_CASE(installer_missing_length)
{
  unfold::http::HttpServer server;
  server.add_file("/workrave-1.11.0-alpha.1.exe", "junk");
  server.add_file("/installer.sh", "installer.sh");
  server.run();

  std::string appcast_str =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\"\n"
    "    xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Workrave Test Appcast</title>\n"
    "        <description>Most recent updates to Workrave Test</description>\n"
    "        <language>en</language>\n"
    "        <link>https://workrave.org/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure url=\"https://127.0.0.1:1337/workrave-1.11.0-alpha.1.exe\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_string(appcast_str);

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  auto verifier = std::make_shared<SignatureVerifierMock>();

  Installer installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          BOOST_CHECK_EQUAL(rc.has_error(), true);
          BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InstallerVerificationFailed);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(installer_incorrect_length)
{
  unfold::http::HttpServer server;
  server.add_file("/workrave-1.11.0-alpha.1.exe", "junk");
  server.add_file("/installer.sh", "installer.sh");
  server.run();

  std::string appcast_str =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\"\n"
    "    xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Workrave Test Appcast</title>\n"
    "        <description>Most recent updates to Workrave Test</description>\n"
    "        <language>en</language>\n"
    "        <link>https://workrave.org/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure url=\"https://127.0.0.1:1337/workrave-1.11.0-alpha.1.exe\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8191\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_string(appcast_str);

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  auto verifier = std::make_shared<SignatureVerifierMock>();

  Installer installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          BOOST_CHECK_EQUAL(rc.has_error(), true);
          BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InstallerVerificationFailed);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(installer_not_found)
{
  unfold::http::HttpServer server;
  server.run();

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_file("appcast.xml");

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  auto verifier = std::make_shared<SignatureVerifierMock>();

  Installer installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          BOOST_CHECK_EQUAL(rc.has_error(), true);
          BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InstallerDownloadFailed);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(installer_invalid_host)
{
  unfold::http::HttpServer server;
  server.run();

  std::string appcast_str =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\"\n"
    "    xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Workrave Test Appcast</title>\n"
    "        <description>Most recent updates to Workrave Test</description>\n"
    "        <language>en</language>\n"
    "        <link>https://workrave.org/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure url=\"https://300.0.0.1.1:1337/workrave-1.11.0-alpha.1.exe\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8191\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_string(appcast_str);

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  auto verifier = std::make_shared<SignatureVerifierMock>();

  Installer installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          BOOST_CHECK_EQUAL(rc.has_error(), true);
          BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InstallerDownloadFailed);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(installer_invalid_signature)
{
  unfold::http::HttpServer server;
  server.add_file("/installer.sh", "installer.sh");
  server.run();

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_file("appcast.xml");

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  auto verifier = std::make_shared<SignatureVerifierMock>();

  EXPECT_CALL(*verifier, set_key(_, _)).Times(0);

  EXPECT_CALL(*verifier, verify(_, _))
    .Times(AtLeast(1))
    .WillRepeatedly(Return(outcome::failure(unfold::crypto::SignatureVerifierErrc::Mismatch)));

  Installer installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          BOOST_CHECK_EQUAL(rc.has_error(), true);
          BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InstallerVerificationFailed);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(installer_failed_to_install)
{
  unfold::http::HttpServer server;
  server.add_file("/installer.sh", "installer.sh");
  server.run();

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_file("appcast.xml");

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  auto verifier = std::make_shared<unfold::crypto::SignatureVerifier>();
  auto rc = verifier->set_key(unfold::crypto::SignatureAlgorithmType::ECDSA,
                              "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  // EXPECT_CALL(*verifier, set_key(_, _)).Times(0);

  // EXPECT_CALL(*verifier, verify(_, _))
  //   .Times(AtLeast(1))
  //   .WillRepeatedly(Return(outcome::failure(unfold::crypto::SignatureVerifierErrc::Mismatch)));

  Installer installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          BOOST_CHECK_EQUAL(rc.has_error(), true);
          BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InstallerExecutionFailed);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

enum class TerminateHookType
{
  NoTerminateHook,
  NoTerminate,
  Terminate
};
inline std::ostream &
operator<<(std::ostream &os, TerminateHookType type)
{
  switch (type)
    {
    case TerminateHookType::NoTerminateHook:
      os << "NoTerminateHook";
      break;
    case TerminateHookType::NoTerminate:
      os << "NoTerminate";
      break;
    case TerminateHookType::Terminate:
      os << "Terminate";
      break;
    }
  return os;
}

BOOST_DATA_TEST_CASE(installer_started_installer,
                     boost::unit_test::data::make(
                       {TerminateHookType::NoTerminateHook, TerminateHookType::NoTerminate, TerminateHookType::Terminate}),
                     do_terminate)
{
  unfold::http::HttpServer server;
  server.add_file("/installer.exe", "test-installer.exe");
  server.run();

  std::error_code ec;
  std::uintmax_t size = std::filesystem::file_size("test-installer.exe", ec);

  std::string appcast_str =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\"\n"
    "    xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Workrave Test Appcast</title>\n"
    "        <description>Most recent updates to Workrave Test</description>\n"
    "        <language>en</language>\n"
    "        <link>https://workrave.org/</link>\n"
    "        <item>\n"
    "            <title>Version 1.1/0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure url=\"https://127.0.0.1:1337/installer.exe\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"" + std::to_string(size) + "\" type=\"application/octet-stream\" />\n"    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_string(appcast_str);

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  if (do_terminate != TerminateHookType::NoTerminateHook)
    {
      hooks->hook_terminate() = [do_terminate]() { return do_terminate == TerminateHookType::Terminate; };
    }

  auto verifier = std::make_shared<SignatureVerifierMock>();
  EXPECT_CALL(*verifier, set_key(_, _)).Times(0);
  EXPECT_CALL(*verifier, verify(_, _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  std::filesystem::remove("installer.log");

  auto platform = std::make_shared<TestPlatform>();

  Installer installer(platform, http, verifier, hooks);

  double last_progress = 0.0;
  installer.set_download_progress_callback([&last_progress](auto progress) {
    BOOST_CHECK_GE(progress, last_progress);
    last_progress = progress;
  });
  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
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
  BOOST_CHECK_GE(100, last_progress);

  int tries = 100;
  bool found = false;
  do
    {
      found = std::filesystem::exists("installer.log");
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  while (tries > 0 && !found);
  BOOST_CHECK(found);

  BOOST_CHECK_EQUAL(platform->is_terminated(), do_terminate != TerminateHookType::NoTerminate);

  server.stop();
}

BOOST_AUTO_TEST_CASE(upgrade_invalid_key)
{
  unfold::utils::IOContext io_context{1};
  UpgradeControl control(std::make_shared<TestPlatform>(), io_context);

  auto rc = control.set_signature_verification_key("xxxxMCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=xxx");
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InvalidArgument);
}

BOOST_AUTO_TEST_CASE(upgrade_invalid_cert)
{
  unfold::utils::IOContext io_context{1};
  UpgradeControl control(std::make_shared<TestPlatform>(), io_context);

  auto rc = control.set_certificate("cert");
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InvalidArgument);
}

BOOST_AUTO_TEST_CASE(upgrade_control_check)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.add_file("/workrave-1.11.0-alpha.1.exe", "junk");
  server.add_file("/installer.sh", "installer.sh");
  server.run();

  unfold::utils::IOContext io_context{1};
  UpgradeControl control(std::make_shared<TestPlatform>(), io_context);

  auto rc = control.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_certificate(cert);
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
          auto rc = co_await control.check_for_updates();
          BOOST_CHECK_EQUAL(rc.has_error(), false);

          // TODO: fails on Wndows
          // auto ri = co_await control.install();
          // BOOST_CHECK_EQUAL(ri.has_error(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(upgrade_control_periodic_check)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.add_file("/workrave-1.11.0-alpha.1.exe", "junk");
  server.add_file("/installer.sh", "installer.sh");
  server.run();

  unfold::utils::IOContext io_context{1};
  UpgradeControl control(std::make_shared<TestPlatform>(), io_context);

  auto rc = control.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_certificate(cert);
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_signature_verification_key("MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_current_version("1.10.45");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control.set_periodic_update_check_interval(std::chrono::seconds{1});
  control.set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    co_return unfold::UpdateResponse::Later;
  });

  control.set_periodic_update_check_enabled(true);

  io_context.wait();
  server.stop();
}

BOOST_AUTO_TEST_SUITE_END()
