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
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include "AppCast.hh"
#include "Hooks.hh"
#include "SignatureVerifierMock.hh"
#include "SigstoreVerifierMock.hh"
#include "TestBase.hh"
#include "TestPlatform.hh"
#include "UpgradeInstaller.hh"
#include "crypto/SignatureVerifierErrors.hh"
#include "http/HttpClient.hh"
#include "http/HttpServer.hh"
#include "unfold/UnfoldErrors.hh"
#include "utils/TestUtils.hh"

using ::testing::_;
using ::testing::An;
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

TEST(Installer, MissingUrl)
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
  EXPECT_EQ(appcast, nullptr);
}

TEST(Installer, MissingLength)
{
  unfold::http::HttpServer server;
  server.add_file("/workrave-1.11.0-alpha.1.exe", find_test_data_file("junk"));
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
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  auto signature_verifier = std::make_shared<SignatureVerifierMock>();
  auto sigstore_verifier = std::make_shared<SigstoreVerifierMock>();

  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::string>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, signature_verifier, sigstore_verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          EXPECT_EQ(rc.has_error(), true);
          EXPECT_EQ(rc.error(), unfold::UnfoldErrc::InstallerVerificationFailed);
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

TEST(Installer, IncorrectLength)
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
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure url=\"https://127.0.0.1:1337/workrave-1.11.0-alpha.1.exe\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8191\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_string(appcast_str);
  EXPECT_NE(appcast, nullptr);
}

TEST(Installer, NotFound)
{
  unfold::http::HttpServer server;
  server.run();

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_file(find_test_data_file("appcast.xml"));

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  auto signature_verifier = std::make_shared<SignatureVerifierMock>();
  auto sigstore_verifier = std::make_shared<SigstoreVerifierMock>();

  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::string>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, signature_verifier, sigstore_verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          EXPECT_EQ(rc.has_error(), true);
          EXPECT_EQ(rc.error(), unfold::UnfoldErrc::InstallerDownloadFailed);
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

TEST(Installer, InvalidHost)
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
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  auto signature_verifier = std::make_shared<SignatureVerifierMock>();
  auto sigstore_verifier = std::make_shared<SigstoreVerifierMock>();

  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::string>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, signature_verifier, sigstore_verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          EXPECT_EQ(rc.has_error(), true);
          EXPECT_EQ(rc.error(), unfold::UnfoldErrc::InstallerDownloadFailed);
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

TEST(Installer, InvalidSignature)
{
  unfold::http::HttpServer server;
  server.add_file("/dummy.exe", find_test_bin_file("test-installer.exe"));
  server.run();

  std::error_code ec;
  std::uintmax_t size = std::filesystem::file_size(find_test_bin_file("test-installer.exe"), ec);

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_file(find_test_data_file("appcast.xml"));
  appcast->items.front()->enclosure->length = size;

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  auto signature_verifier = std::make_shared<SignatureVerifierMock>();
  auto sigstore_verifier = std::make_shared<SigstoreVerifierMock>();

  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::string>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));

  EXPECT_CALL(*signature_verifier, set_key(_, _)).Times(0);

  EXPECT_CALL(*signature_verifier, verify(_, _))
    .Times(AtLeast(1))
    .WillRepeatedly(Return(outcome::failure(unfold::crypto::SignatureVerifierErrc::Mismatch)));

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, signature_verifier, sigstore_verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          EXPECT_EQ(rc.has_error(), true);
          EXPECT_EQ(rc.error(), unfold::UnfoldErrc::InstallerVerificationFailed);
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

TEST(Installer, FailedToInstall)
{
  unfold::http::HttpServer server;
  server.add_file("/dummy.exe", find_test_data_file("junk"));
  server.run();

  std::error_code ec;
  std::uintmax_t size = std::filesystem::file_size(find_test_data_file("junk"), ec);

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_file(find_test_data_file("appcast.xml"));
  appcast->items.front()->enclosure->length = size;

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  auto signature_verifier = std::make_shared<SignatureVerifierMock>();
  auto sigstore_verifier = std::make_shared<SigstoreVerifierMock>();

  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::string>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));
  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::filesystem::path>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));

  EXPECT_CALL(*signature_verifier, set_key(_, _)).Times(0);

  EXPECT_CALL(*signature_verifier, verify(_, _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, signature_verifier, sigstore_verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          EXPECT_EQ(rc.has_error(), true);
          EXPECT_EQ(rc.error(), unfold::UnfoldErrc::InstallerExecutionFailed);
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

TEST(Installer, SigstoreVerificationFailed)
{
  unfold::http::HttpServer server;
  server.add_file("/dummy.exe", find_test_bin_file("test-installer.exe"));
  server.run();

  std::error_code ec;
  std::uintmax_t size = std::filesystem::file_size(find_test_data_file("test-installer.exe"), ec);

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_file(find_test_data_file("appcast.xml"));
  appcast->items.front()->enclosure->length = size;

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  auto signature_verifier = std::make_shared<SignatureVerifierMock>();
  auto sigstore_verifier = std::make_shared<SigstoreVerifierMock>();

  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::string>()))
    .WillRepeatedly(
      InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return unfold::UnfoldErrc::InstallerVerificationFailed; }));

  EXPECT_CALL(*signature_verifier, set_key(_, _)).Times(0);

  EXPECT_CALL(*signature_verifier, verify(_, _)).Times(0);

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, signature_verifier, sigstore_verifier, hooks);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          EXPECT_EQ(rc.has_error(), true);
          EXPECT_EQ(rc.error(), unfold::UnfoldErrc::InstallerVerificationFailed);
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

class InstallerTest : public ::testing::TestWithParam<TerminateHookType>

{
};

TEST_P(InstallerTest, InstallerStartedInstaller)
{
  TerminateHookType do_terminate = GetParam();

  unfold::http::HttpServer server;
  server.add_file("/dummy.exe", find_test_bin_file("test-installer.exe"));
  server.run();

  std::error_code ec;
  std::uintmax_t size = std::filesystem::file_size(find_test_bin_file("test-installer.exe"), ec);

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
    "            <enclosure url=\"https://127.0.0.1:1337/dummy.exe\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"" + std::to_string(size) + "\" type=\"application/octet-stream\" />\n"    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_string(appcast_str);

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  if (do_terminate != TerminateHookType::NoTerminateHook)
    {
      hooks->hook_terminate() = [do_terminate]() { return do_terminate == TerminateHookType::Terminate; };
    }

  auto signature_verifier = std::make_shared<SignatureVerifierMock>();
  EXPECT_CALL(*signature_verifier, set_key(_, _)).Times(0);
  EXPECT_CALL(*signature_verifier, verify(_, _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  auto sigstore_verifier = std::make_shared<SigstoreVerifierMock>();

  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::string>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));
  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::filesystem::path>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));

  std::filesystem::remove("installer.log");

  auto platform = std::make_shared<TestPlatform>();

  UpgradeInstaller installer(platform, http, signature_verifier, sigstore_verifier, hooks);

  double last_progress = 0.0;
  std::optional<unfold::UpdateStage> last_stage;
  installer.set_download_progress_callback([&last_stage, &last_progress](unfold::UpdateStage stage, auto progress) {
    if (stage == unfold::UpdateStage::DownloadInstaller)
      {
        EXPECT_GE(progress, last_progress);
        last_progress = progress;
      }

    if (!last_stage)
      {
        EXPECT_EQ(stage, unfold::UpdateStage::DownloadInstaller);
      }
    else if (*last_stage == unfold::UpdateStage::DownloadInstaller)
      {
        EXPECT_TRUE(stage == unfold::UpdateStage::DownloadInstaller || stage == unfold::UpdateStage::VerifyInstaller);
      }
    else
      {
        EXPECT_EQ(stage, *last_stage + 1);
      }
    last_stage = stage;
  });

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          EXPECT_EQ(rc.has_error(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  EXPECT_GE(100, last_progress);

  int tries = 100;
  bool found = false;
  do
    {
      found = std::filesystem::exists("installer.log");
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      tries--;
    }
  while (tries > 0 && !found);
  EXPECT_TRUE(found);

  EXPECT_EQ(platform->is_terminated(), do_terminate != TerminateHookType::NoTerminate);

  server.stop();
}

INSTANTIATE_TEST_SUITE_P(TerminateHookTypes,
                         InstallerTest,
                         ::testing::Values(TerminateHookType::NoTerminateHook, TerminateHookType::NoTerminate, TerminateHookType::Terminate));

TEST(Installer, StartedInstallerWithArgs)
{
  unfold::http::HttpServer server;
  server.add_file("/dummy.exe", find_test_bin_file("test-installer.exe"));
  server.run();

  std::error_code ec;
  std::uintmax_t size = std::filesystem::file_size(find_test_bin_file("test-installer.exe"), ec);

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
    "            <enclosure url=\"https://127.0.0.1:1337/dummy.exe\" sparkle:installerArguments=\"/SILENT /SP- /NOICONS\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"" + std::to_string(size) + "\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_string(appcast_str);

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();

  auto signature_verifier = std::make_shared<SignatureVerifierMock>();
  EXPECT_CALL(*signature_verifier, set_key(_, _)).Times(0);
  EXPECT_CALL(*signature_verifier, verify(_, _)).Times(AtLeast(1)).WillRepeatedly(Return(outcome::success()));

  auto sigstore_verifier = std::make_shared<SigstoreVerifierMock>();

  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::string>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));
  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::filesystem::path>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));

  std::filesystem::remove("installer.log");

  auto platform = std::make_shared<TestPlatform>();

  UpgradeInstaller installer(platform, http, signature_verifier, sigstore_verifier, hooks);

  double last_progress = 0.0;
  std::optional<unfold::UpdateStage> last_stage;
  installer.set_download_progress_callback([&last_stage, &last_progress](unfold::UpdateStage stage, auto progress) {
    if (stage == unfold::UpdateStage::DownloadInstaller)
      {
        EXPECT_GE(progress, last_progress);
        last_progress = progress;
      }

    if (!last_stage)
      {
        EXPECT_EQ(stage, unfold::UpdateStage::DownloadInstaller);
      }
    else if (*last_stage == unfold::UpdateStage::DownloadInstaller)
      {
        EXPECT_TRUE(stage == unfold::UpdateStage::DownloadInstaller || stage == unfold::UpdateStage::VerifyInstaller);
      }
    else
      {
        EXPECT_EQ(stage, *last_stage + 1);
      }
    last_stage = stage;
  });

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          EXPECT_EQ(rc.has_error(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();
  EXPECT_GE(100, last_progress);

  int tries = 100;
  bool found = false;
  do
    {
      found = std::filesystem::exists("installer.log");
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      tries--;
    }
  while (tries > 0 && !found);
  EXPECT_TRUE(found);

  if (found)
    {
      std::string s;
      std::vector<std::string> lines;
      std::ifstream fin("installer.log");
      while (std::getline(fin, s))
        {
          lines.push_back(s);
        }
      EXPECT_EQ(lines[0], "Hello world!");
      EXPECT_EQ(lines[2], "/SILENT");
      EXPECT_EQ(lines[3], "/SP-");
      EXPECT_EQ(lines[4], "/NOICONS");
    }
  server.stop();
}

TEST(Installer, ValidationCallbackAccept)
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
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure url=\"https://127.0.0.1:1337/workrave-1.11.0-alpha.1.exe\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8192\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_string(appcast_str);

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();
  auto signature_verifier = std::make_shared<SignatureVerifierMock>();
  auto sigstore_verifier = std::make_shared<SigstoreVerifierMock>();

  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::string>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, signature_verifier, sigstore_verifier, hooks);

  bool validation_called = false;
  installer.set_installer_validation_callback([&](const std::string &installer_path) -> outcome::std_result<bool> {
    validation_called = true;
    return outcome::success(true); // Accept the installer
  });

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          // This test will fail due to connection error, not validation
          EXPECT_TRUE(rc.has_error());
          // Validation callback should not be called since download fails
          EXPECT_FALSE(validation_called);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();
}

TEST(Installer, ValidationCallbackReject)
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
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure url=\"https://127.0.0.1:1337/workrave-1.11.0-alpha.1.exe\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"8192\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  auto appcast = reader->load_from_string(appcast_str);

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto hooks = std::make_shared<Hooks>();
  auto signature_verifier = std::make_shared<SignatureVerifierMock>();
  auto sigstore_verifier = std::make_shared<SigstoreVerifierMock>();

  EXPECT_CALL(*sigstore_verifier, verify(An<std::string>(), An<std::string>()))
    .WillRepeatedly(InvokeWithoutArgs([]() -> boost::asio::awaitable<outcome::std_result<void>> { co_return outcome::success(); }));

  UpgradeInstaller installer(std::make_shared<TestPlatform>(), http, signature_verifier, sigstore_verifier, hooks);

  bool validation_called = false;
  installer.set_installer_validation_callback([&](const std::string &installer_path) -> outcome::std_result<bool> {
    validation_called = true;
    return outcome::success(false); // Reject the installer
  });

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await installer.install(appcast->items.front());
          EXPECT_TRUE(rc.has_error());
          EXPECT_EQ(rc.error(), unfold::UnfoldErrc::InstallerDownloadFailed);
          EXPECT_FALSE(validation_called);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          EXPECT_TRUE(false);
        }
    },
    boost::asio::detached);
  ioc.run();
}
