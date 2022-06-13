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

#include <boost/outcome/success_failure.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>
#include <spdlog/spdlog.h>

#include "http/HttpServer.hh"
#include "http/HttpClient.hh"
#include "unfold/UnfoldErrors.hh"

#include "AppCast.hh"
#include "Fixture.hpp"
#include "Hooks.hh"
#include "UpgradeInstaller.hh"
#include "SignatureVerifierMock.hh"
#include "TestPlatform.hh"

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

BOOST_FIXTURE_TEST_SUITE(unfold_installer_test, Fixture)

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

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

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

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

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

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

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

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

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

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

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
  server.add_file("/installer.exe", "test-installer.exe");
  server.run();

  std::error_code ec;
  std::uintmax_t size = std::filesystem::file_size("test-installer.exe", ec);

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_file("appcast.xml");
  appcast->items.front()->enclosure->length = size;

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  auto verifier = std::make_shared<SignatureVerifierMock>();

  EXPECT_CALL(*verifier, set_key(_, _)).Times(0);

  EXPECT_CALL(*verifier, verify(_, _))
    .Times(AtLeast(1))
    .WillRepeatedly(Return(outcome::failure(unfold::crypto::SignatureVerifierErrc::Mismatch)));

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

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
  server.add_file("/installer.exe", "junk");
  server.run();

  std::error_code ec;
  std::uintmax_t size = std::filesystem::file_size("junk", ec);

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_file("appcast.xml");
  appcast->items.front()->enclosure->length = size;

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto carc = http->add_ca_cert(cert);
  BOOST_CHECK_EQUAL(carc.has_error(), false);

  auto hooks = std::make_shared<Hooks>();

  auto verifier = std::make_shared<SignatureVerifierMock>();

  EXPECT_CALL(*verifier, set_key(_, _)).Times(0);

  EXPECT_CALL(*verifier, verify(_, _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, verifier, hooks);

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

  UpgradeInstaller installer(platform, http, verifier, hooks);

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
      tries--;
    }
  while (tries > 0 && !found);
  BOOST_CHECK(found);

  BOOST_CHECK_EQUAL(platform->is_terminated(), do_terminate != TerminateHookType::NoTerminate);

  server.stop();
}

BOOST_AUTO_TEST_SUITE_END()
