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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <chrono>
#include <spdlog/spdlog.h>

#include "unfold/UnfoldErrors.hh"
#include "http/HttpServer.hh"
#include "utils/DateUtils.hh"

#include "TestPlatform.hh"
#include "UpgradeChecker.hh"

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

TEST(CheckerTest, AppcastNotFound)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcastxxx.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.12.0");
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), true);
          EXPECT_EQ(check_result.error(), unfold::UnfoldErrc::AppcastDownloadFailed);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, InvalidHost)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://300.0.0.1.2:1337/appcastxxx.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.12.0");
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), true);
          EXPECT_EQ(check_result.error(), unfold::UnfoldErrc::AppcastDownloadFailed);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, InvalidVersion)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_current_version("1.12.0.1.2");
  EXPECT_EQ(rc.has_error(), true);
}

TEST(CheckerTest, InvalidAppcast)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "invalidappcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), true);
          EXPECT_EQ(check_result.error(), unfold::UnfoldErrc::InvalidAppcast);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, EmptyAppcast)
{
  unfold::http::HttpServer server;
  server.add("/appcast.xml", "");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), true);
          EXPECT_EQ(check_result.error(), unfold::UnfoldErrc::InvalidAppcast);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, InvalidItemsInAppcast)
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
    "            <enclosure os=\"windows\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8192\" type=\"application/octet-stream\" url=\"https://example.com/workrave-win32-v4.0.0.exe\"/>\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  unfold::http::HttpServer server;
  server.add("/appcast.xml", appcast_str);
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.0.0");
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), true);

          auto appcast = checker.get_selected_update();
          EXPECT_EQ(appcast, nullptr);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, NoUpgrade)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.12.0");
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), false);
          EXPECT_EQ(check_result.value(), false);

          auto appcast = checker.get_selected_update();
          EXPECT_EQ(appcast.get(), nullptr);
          auto info = checker.get_update_info();
          EXPECT_EQ(info.get(), nullptr);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, HasUpgrade)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), false);
          EXPECT_EQ(check_result.value(), true);

          auto appcast = checker.get_selected_update();
          EXPECT_EQ(appcast->version, "1.11.0-alpha.1");
          EXPECT_EQ(appcast->publication_date, "Sun, 27 Feb 2022 11:02:33 +0100");
          EXPECT_EQ(appcast->title, "Workrave 1.11.0-alpha.1");
          auto info = checker.get_update_info();
          EXPECT_EQ(info->title, "Workrave");
          EXPECT_EQ(info->current_version, "1.10.48");
          EXPECT_EQ(info->version, "1.11.0-alpha.1");
          EXPECT_EQ(info->release_notes.size(), 2);
          EXPECT_EQ(info->release_notes.front().version, "1.11.0-alpha.1");
          EXPECT_EQ(info->release_notes.front().date, "Sun, 27 Feb 2022 11:02:33 +0100");
          EXPECT_EQ(info->release_notes.back().version, "1.10.49");
          EXPECT_EQ(info->release_notes.back().date, "Wed, 05 Jan 2022 03:05:19 +0100");
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, Delay)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast-canary.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.0.0");
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto delay = checker.get_rollout_delay_for_priority(0);
          EXPECT_EQ(delay, std::chrono::seconds(0));

          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), false);
          EXPECT_EQ(check_result.value(), true);

          // <unfold:canary>
          //     <interval>
          //         <percentage>10</percentage>
          //         <days>2</days>
          //     </interval>
          //     <interval>
          //         <percentage>15</percentage>
          //         <days>3</days>
          //     </interval>
          //     <interval>
          //         <percentage>30</percentage>
          //         <days>5</days>
          //         <ignored>5</ignored>
          //     </interval>
          //     <ignored>
          //         <percentage>30</percentage>
          //         <days>5</days>
          //     </ignored>
          // </unfold:canary>

          delay = checker.get_rollout_delay_for_priority(0);
          EXPECT_EQ(delay, std::chrono::seconds(0));
          delay = checker.get_rollout_delay_for_priority(1);
          EXPECT_EQ(delay, std::chrono::seconds(0));
          delay = checker.get_rollout_delay_for_priority(9);
          EXPECT_EQ(delay, std::chrono::seconds(0));
          delay = checker.get_rollout_delay_for_priority(10);
          EXPECT_EQ(delay, std::chrono::seconds(0));
          delay = checker.get_rollout_delay_for_priority(11);
          EXPECT_EQ(delay, std::chrono::seconds(2 * 24 * 60 * 60));
          delay = checker.get_rollout_delay_for_priority(12);
          EXPECT_EQ(delay, std::chrono::seconds(2 * 24 * 60 * 60));
          delay = checker.get_rollout_delay_for_priority(24);
          EXPECT_EQ(delay, std::chrono::seconds(2 * 24 * 60 * 60));
          delay = checker.get_rollout_delay_for_priority(25);
          EXPECT_EQ(delay, std::chrono::seconds(2 * 24 * 60 * 60));
          delay = checker.get_rollout_delay_for_priority(26);
          EXPECT_EQ(delay, std::chrono::seconds(5 * 24 * 60 * 60));
          delay = checker.get_rollout_delay_for_priority(27);
          EXPECT_EQ(delay, std::chrono::seconds(5 * 24 * 60 * 60));
          delay = checker.get_rollout_delay_for_priority(54);
          EXPECT_EQ(delay, std::chrono::seconds(5 * 24 * 60 * 60));
          delay = checker.get_rollout_delay_for_priority(55);
          EXPECT_EQ(delay, std::chrono::seconds(5 * 24 * 60 * 60));
          delay = checker.get_rollout_delay_for_priority(56);
          EXPECT_EQ(delay, std::chrono::seconds(10 * 24 * 60 * 60));
          delay = checker.get_rollout_delay_for_priority(57);
          EXPECT_EQ(delay, std::chrono::seconds(10 * 24 * 60 * 60));
          delay = checker.get_rollout_delay_for_priority(99);
          EXPECT_EQ(delay, std::chrono::seconds(10 * 24 * 60 * 60));
          delay = checker.get_rollout_delay_for_priority(100);
          EXPECT_EQ(delay, std::chrono::seconds(10 * 24 * 60 * 60));
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, EarliestRollout)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast-canary.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.0.0");
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto pub_date = unfold::utils::DateUtils::parse_time_point("Sun, 17 Apr 2022 19:30:14 +0200");

          auto rollout_time = checker.get_earliest_rollout_time_for_priority(0);
          EXPECT_EQ(rollout_time, std::chrono::system_clock::from_time_t(0));

          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), false);
          EXPECT_EQ(check_result.value(), true);

          rollout_time = checker.get_earliest_rollout_time_for_priority(0);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(0));
          rollout_time = checker.get_earliest_rollout_time_for_priority(1);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(0));
          rollout_time = checker.get_earliest_rollout_time_for_priority(9);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(0));
          rollout_time = checker.get_earliest_rollout_time_for_priority(10);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(0));
          rollout_time = checker.get_earliest_rollout_time_for_priority(11);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(2 * 24 * 60 * 60));
          rollout_time = checker.get_earliest_rollout_time_for_priority(12);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(2 * 24 * 60 * 60));
          rollout_time = checker.get_earliest_rollout_time_for_priority(24);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(2 * 24 * 60 * 60));
          rollout_time = checker.get_earliest_rollout_time_for_priority(25);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(2 * 24 * 60 * 60));
          rollout_time = checker.get_earliest_rollout_time_for_priority(26);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(5 * 24 * 60 * 60));
          rollout_time = checker.get_earliest_rollout_time_for_priority(27);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(5 * 24 * 60 * 60));
          rollout_time = checker.get_earliest_rollout_time_for_priority(54);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(5 * 24 * 60 * 60));
          rollout_time = checker.get_earliest_rollout_time_for_priority(55);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(5 * 24 * 60 * 60));
          rollout_time = checker.get_earliest_rollout_time_for_priority(56);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(10 * 24 * 60 * 60));
          rollout_time = checker.get_earliest_rollout_time_for_priority(57);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(10 * 24 * 60 * 60));
          rollout_time = checker.get_earliest_rollout_time_for_priority(99);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(10 * 24 * 60 * 60));
          rollout_time = checker.get_earliest_rollout_time_for_priority(100);
          EXPECT_EQ(rollout_time, pub_date + std::chrono::seconds(10 * 24 * 60 * 60));
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, ChannelsAllowedNone)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast-channels.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), false);
          EXPECT_EQ(check_result.value(), true);

          auto appcast = checker.get_selected_update();
          EXPECT_EQ(appcast->version, "1.11.0-alpha.3");
          EXPECT_EQ(appcast->publication_date, "Thu, 30 Jun 2022 04:53:59 +0200");
          EXPECT_EQ(appcast->title, "Workrave 1.11.0-alpha.3");
          auto info = checker.get_update_info();
          EXPECT_EQ(info->title, "Workrave");
          EXPECT_EQ(info->current_version, "1.10.48");
          EXPECT_EQ(info->version, "1.11.0-alpha.3");
          EXPECT_EQ(info->release_notes.size(), 4);
          EXPECT_EQ(info->release_notes.front().version, "1.11.0-alpha.3");
          EXPECT_EQ(info->release_notes.front().date, "Thu, 30 Jun 2022 04:53:59 +0200");
          EXPECT_EQ(info->release_notes.back().version, "1.10.49");
          EXPECT_EQ(info->release_notes.back().date, "Wed, 05 Jan 2022 03:05:19 +0100");
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, ChannelsAllowedAlpha)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast-channels.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_allowed_channels({"release", "alpha"});
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), false);
          EXPECT_EQ(check_result.value(), true);

          auto appcast = checker.get_selected_update();
          EXPECT_EQ(appcast->version, "1.11.0-alpha.3");
          EXPECT_EQ(appcast->publication_date, "Thu, 30 Jun 2022 04:53:59 +0200");
          EXPECT_EQ(appcast->title, "Workrave 1.11.0-alpha.3");
          auto info = checker.get_update_info();
          EXPECT_EQ(info->title, "Workrave");
          EXPECT_EQ(info->current_version, "1.10.48");
          EXPECT_EQ(info->version, "1.11.0-alpha.3");
          EXPECT_EQ(info->release_notes.size(), 4);
          EXPECT_EQ(info->release_notes.front().version, "1.11.0-alpha.3");
          EXPECT_EQ(info->release_notes.front().date, "Thu, 30 Jun 2022 04:53:59 +0200");
          EXPECT_EQ(info->release_notes.back().version, "1.10.49");
          EXPECT_EQ(info->release_notes.back().date, "Wed, 05 Jan 2022 03:05:19 +0100");
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, ChannelsAllowedRelease)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast-channels.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.10.47");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_allowed_channels({"release"});
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), false);
          EXPECT_EQ(check_result.value(), true);

          auto appcast = checker.get_selected_update();
          EXPECT_EQ(appcast->version, "1.10.49");
          EXPECT_EQ(appcast->publication_date, "Wed, 05 Jan 2022 03:05:19 +0100");
          EXPECT_EQ(appcast->title, "Workrave 1.10.49");
          auto info = checker.get_update_info();
          EXPECT_EQ(info->title, "Workrave");
          EXPECT_EQ(info->current_version, "1.10.47");
          EXPECT_EQ(info->version, "1.10.49");
          EXPECT_EQ(info->release_notes.size(), 2);
          EXPECT_EQ(info->release_notes.front().version, "1.10.49");
          EXPECT_EQ(info->release_notes.front().date, "Wed, 05 Jan 2022 03:05:19 +0100");
          EXPECT_EQ(info->release_notes.back().version, "1.10.48");
          EXPECT_EQ(info->release_notes.back().date, "Tue, 03 Aug 2021 05:26:00 +0200");
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, ChannelsAllowedEmpty)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast-channels.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_allowed_channels({});
  EXPECT_EQ(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), false);
          EXPECT_EQ(check_result.value(), true);

          auto appcast = checker.get_selected_update();
          EXPECT_EQ(appcast->version, "1.11.0-alpha.3");
          EXPECT_EQ(appcast->publication_date, "Thu, 30 Jun 2022 04:53:59 +0200");
          EXPECT_EQ(appcast->title, "Workrave 1.11.0-alpha.3");
          auto info = checker.get_update_info();
          EXPECT_EQ(info->title, "Workrave");
          EXPECT_EQ(info->current_version, "1.10.48");
          EXPECT_EQ(info->version, "1.11.0-alpha.3");
          EXPECT_EQ(info->release_notes.size(), 4);
          EXPECT_EQ(info->release_notes.front().version, "1.11.0-alpha.3");
          EXPECT_EQ(info->release_notes.front().date, "Thu, 30 Jun 2022 04:53:59 +0200");
          EXPECT_EQ(info->release_notes.back().version, "1.10.49");
          EXPECT_EQ(info->release_notes.back().date, "Wed, 05 Jan 2022 03:05:19 +0100");
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, UpdateValidationCallbackAccept)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  EXPECT_EQ(rc.has_error(), false);

  bool validation_called = false;
  checker.set_update_validation_callback([&](const unfold::UpdateInfo &update_info) -> outcome::std_result<bool> {
    validation_called = true;
    EXPECT_EQ(update_info.version, "1.11.0-alpha.1");
    return outcome::success(true); // Accept the update
  });

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), false);
          EXPECT_EQ(check_result.value(), true);
          EXPECT_TRUE(validation_called);

          auto appcast = checker.get_selected_update();
          EXPECT_EQ(appcast->version, "1.11.0-alpha.1");
          EXPECT_EQ(appcast->publication_date, "Sun, 27 Feb 2022 11:02:33 +0100");
          EXPECT_EQ(appcast->title, "Workrave 1.11.0-alpha.1");

          // Verify that update info is still available after validation
          auto info = checker.get_update_info();
          EXPECT_NE(info, nullptr);
          EXPECT_EQ(info->title, "Workrave");
          EXPECT_EQ(info->current_version, "1.10.48");
          EXPECT_EQ(info->version, "1.11.0-alpha.1");
          EXPECT_EQ(info->release_notes.size(), 2);
          EXPECT_EQ(info->release_notes.front().version, "1.11.0-alpha.1");
          EXPECT_EQ(info->release_notes.front().date, "Sun, 27 Feb 2022 11:02:33 +0100");
          EXPECT_EQ(info->release_notes.back().version, "1.10.49");
          EXPECT_EQ(info->release_notes.back().date, "Wed, 05 Jan 2022 03:05:19 +0100");
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, UpdateValidationCallbackReject)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  EXPECT_EQ(rc.has_error(), false);

  bool validation_called = false;
  checker.set_update_validation_callback([&](const unfold::UpdateInfo &update_info) -> outcome::std_result<bool> {
    validation_called = true;
    EXPECT_EQ(update_info.version, "1.11.0-alpha.1");
    return outcome::success(false); // Reject the update
  });

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), false);
          EXPECT_EQ(check_result.value(), false); // Should return false (no update) when rejected
          EXPECT_TRUE(validation_called);

          // Verify that update info is cleared after rejection
          auto info = checker.get_update_info();
          EXPECT_EQ(info, nullptr);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

TEST(CheckerTest, UpdateValidationCallbackError)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  UpgradeChecker checker(std::make_shared<TestPlatform>(), http, hooks);

  auto rc = checker.set_appcast("https://127.0.0.1:1337/appcast.xml");
  EXPECT_EQ(rc.has_error(), false);

  rc = checker.set_current_version("1.10.48");
  EXPECT_EQ(rc.has_error(), false);

  bool validation_called = false;
  checker.set_update_validation_callback([&](const unfold::UpdateInfo &update_info) -> outcome::std_result<bool> {
    validation_called = true;
    return outcome::failure(unfold::UnfoldErrc::InternalError); // Validation error
  });

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto check_result = co_await checker.check_for_update();
          EXPECT_EQ(check_result.has_error(), true);
          EXPECT_EQ(check_result.error(), unfold::UnfoldErrc::InternalError);
          EXPECT_TRUE(validation_called);

          // Verify that update info is cleared after rejection
          auto info = checker.get_update_info();
          EXPECT_EQ(info, nullptr);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}
