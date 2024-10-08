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

#include <memory>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#if SPDLOG_VERSION >= 10600
#  include <spdlog/pattern_formatter.h>
#endif
#if SPDLOG_VERSION >= 10801
#  include <spdlog/cfg/env.h>
#endif

#include "http/HttpServer.hh"

#include "http/HttpClient.hh"
#include "http/HttpClientErrors.hh"
#include "http/Options.hh"
#include "utils/Logging.hh"

using namespace unfold::http;
using namespace unfold::utils;

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

struct GlobalFixture : public ::testing::Environment
{
  GlobalFixture() = default;
  ~GlobalFixture() = default;

  GlobalFixture(const GlobalFixture &) = delete;
  GlobalFixture &operator=(const GlobalFixture &) = delete;
  GlobalFixture(GlobalFixture &&) = delete;
  GlobalFixture &operator=(GlobalFixture &&) = delete;

  void SetUp() override
  {
    const auto *log_file = "unfold-test-http.log";

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

  void TearDown() override
  {
    spdlog::drop_all();
  }
};

struct HttpTest : public ::testing::Test
{
  HttpTest() = default;
  ~HttpTest() = default;

  HttpTest(const HttpTest &) = delete;
  HttpTest &operator=(const HttpTest &) = delete;
  HttpTest(HttpTest &&) = delete;
  HttpTest &operator=(HttpTest &&) = delete;

  outcome::std_result<Response> get_sync(std::shared_ptr<HttpClient> http, std::string url, std::string file, ProgressCallback cb)
  {
    boost::asio::io_context ioc;
    outcome::std_result<Response> ret = outcome::failure(HttpClientErrc::InternalError);
    boost::asio::co_spawn(
      ioc,
      [&]() -> boost::asio::awaitable<void> { ret = co_await http->get(url, file, cb); },
      boost::asio::detached);
    ioc.run();
    ioc.restart();
    return ret;
  }

  outcome::std_result<Response> get_sync(std::shared_ptr<HttpClient> http, std::string url)
  {
    boost::asio::io_context ioc;
    outcome::std_result<Response> ret = outcome::failure(HttpClientErrc::InternalError);

    boost::asio::co_spawn(ioc, [&]() -> boost::asio::awaitable<void> { ret = co_await http->get(url); }, boost::asio::detached);
    ioc.run();
    ioc.restart();
    return ret;
  }

private:
  std::shared_ptr<spdlog::logger> logger{Logging::create("test")};
};

TEST_F(HttpTest, http_client_get_secure)
{
  HttpServer server;
  server.add("/foo", "foo\n");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://127.0.0.1:1337/foo");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "foo\n");
    }

  server.stop();
}

TEST_F(HttpTest, http_client_get_secure_many)
{
  HttpServer server1;
  server1.add("/foo", "foo\n");
  server1.add("/bar", "bar\n");
  server1.run();

  HttpServer server2(Protocol::Secure, 1338);
  server2.add("/foo", "foo\n");
  server2.add("/bar", "bar\n");
  server2.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://127.0.0.1:1337/foo");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "foo\n");
    }

  rc = get_sync(http, "https://127.0.0.1:1337/bar");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "bar\n");
    }

  rc = get_sync(http, "https://127.0.0.1:1338/foo");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "foo\n");
    }

  rc = get_sync(http, "https://127.0.0.1:1338/bar");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "bar\n");
    }

  rc = get_sync(http, "https://127.0.0.1:1337/bar");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "bar\n");
    }

  server1.stop();
  server2.stop();
}

TEST_F(HttpTest, http_client_get_plain)
{
  HttpServer server(Protocol::Plain);
  server.add("/foo", "foo\n");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "http://127.0.0.1:1337/foo");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "foo\n");
    }

  server.stop();
}

TEST_F(HttpTest, http_client_get_plain_many)
{
  HttpServer server1(Protocol::Plain);
  server1.add("/foo", "foo\n");
  server1.add("/bar", "bar\n");
  server1.run();

  HttpServer server2(Protocol::Plain, 1338);
  server2.add("/foo", "foo\n");
  server2.add("/bar", "bar\n");
  server2.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "http://127.0.0.1:1337/foo");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "foo\n");
    }

  rc = get_sync(http, "http://127.0.0.1:1337/bar");
  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "bar\n");
    }

  rc = get_sync(http, "http://127.0.0.1:1338/foo");
  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "foo\n");
    }

  rc = get_sync(http, "http://127.0.0.1:1337/bar");
  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "bar\n");
    }

  server1.stop();
  server2.stop();
}

TEST_F(HttpTest, http_client_get_plain_special_characters)
{
  HttpServer server(Protocol::Plain);
  server.add("/foo?x=%2f&b=2&c=3", "foo\n");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "http://127.0.0.1:1337/foo?x=%2f&b=2&c=3");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "foo\n");
    }

  server.stop();
}

TEST_F(HttpTest, http_client_not_found)
{
  HttpServer server;
  server.add("/foo", "foo\n");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://127.0.0.1:1337/bar");

  EXPECT_EQ(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 404);
      EXPECT_EQ(content, "The resource '/bar' was not found.");
    }
  server.stop();
}

TEST_F(HttpTest, http_client_host_not_found)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://does-not-exist:1337/bar");
  EXPECT_EQ(rc.error(), HttpClientErrc::NameResolutionFailed);
}

TEST_F(HttpTest, http_client_connection_refused)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://127.0.0.1:1338/bar");
  EXPECT_EQ(rc.error(), HttpClientErrc::ConnectionRefused);
}

TEST_F(HttpTest, http_client_get_file_connection_refused)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://127.0.0.1:1338/foo", "foo.txt", [&](double progress) { EXPECT_TRUE(false); });
  EXPECT_EQ(rc.error(), HttpClientErrc::ConnectionRefused);
}

TEST_F(HttpTest, http_client_invalid_ip_in_url)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://300.1.1.1:1337/bar");
  EXPECT_EQ(rc.error(), HttpClientErrc::NameResolutionFailed);
}

TEST_F(HttpTest, http_client_invalid_url)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "//300.1.1.1:1337:foo:/bar");
  EXPECT_EQ(rc.error(), HttpClientErrc::MalformedURL);
}

TEST_F(HttpTest, http_client_get_file_invalid_url)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "//127.0.0.1:1337:1337/foo", "foo.txt", [&](double progress) { EXPECT_TRUE(false); });
  EXPECT_EQ(rc.error(), HttpClientErrc::MalformedURL);
}

TEST_F(HttpTest, http_client_get_file_secure)
{
  HttpServer server;

  std::string body(4 * 8192, 'x');

  server.add("/foo", body);
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  double previous_progress = 0.0;
  auto rc = get_sync(http, "https://127.0.0.1:1337/foo", "foo.txt", [&](double progress) {
    EXPECT_GE(progress, previous_progress);
    previous_progress = progress;
  });

  EXPECT_EQ(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();

      EXPECT_EQ(result, 200);
      EXPECT_GE(previous_progress + 0.0001, 1.0);
    }
  server.stop();
}

TEST_F(HttpTest, http_client_get_file_plain)
{
  HttpServer server(Protocol::Plain);

  std::string body(4 * 8192, 'x');

  server.add("/foo", body);
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  double previous_progress = 0.0;
  auto rc = get_sync(http, "http://127.0.0.1:1337/foo", "foo.txt", [&](double progress) {
    EXPECT_GE(progress, previous_progress);
    previous_progress = progress;
  });

  EXPECT_EQ(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();

      EXPECT_EQ(result, 200);
      EXPECT_GE(previous_progress + 0.0001, 1.0);
    }
  server.stop();
}

TEST_F(HttpTest, http_client_get_file_not_found)
{
  HttpServer server;

  std::string body(10000, 'x');

  server.add("/foo", body);
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  double previous_progress = 0.0;
  auto rc = get_sync(http, "https://127.0.0.1:1337/bar", "foo.txt", [&](double progress) {
    EXPECT_GE(progress, previous_progress);
    previous_progress = progress;
  });

  EXPECT_EQ(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();

      EXPECT_EQ(result, 404);
      EXPECT_LE(previous_progress, 1);
    }
  server.stop();
}

TEST_F(HttpTest, http_client_redirect_plain_to_secure)
{
  HttpServer plain_server(Protocol::Plain, 1338);
  HttpServer secure_server;

  std::string body(4 * 8192, 'x');

  plain_server.add_redirect("/foo", "https://127.0.0.1:1337/bar");
  plain_server.run();

  secure_server.add("/bar", body);
  secure_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "http://127.0.0.1:1338/foo");

  EXPECT_EQ(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
    }
  secure_server.stop();
  plain_server.stop();
}

TEST_F(HttpTest, http_client_redirect_plain_to_plain_same_server)
{
  HttpServer plain_server("plain1", Protocol::Plain, 1338);

  std::string body(4 * 8192, 'x');

  plain_server.add_redirect("/foo", "/bar");
  plain_server.add("/bar", body);
  plain_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();

  auto rc = get_sync(http, "http://127.0.0.1:1338/foo");

  EXPECT_EQ(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
    }
  plain_server.stop();
}

TEST_F(HttpTest, http_client_redirect_plain_to_plain_same_server_absolute_url)
{
  HttpServer plain_server("plain1", Protocol::Plain, 1338);

  std::string body(4 * 8192, 'x');

  plain_server.add_redirect("/foo", "http://127.0.0.1:1338/bar");
  plain_server.add("/bar", body);
  plain_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();

  auto rc = get_sync(http, "http://127.0.0.1:1338/foo");

  EXPECT_EQ(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
    }
  plain_server.stop();
}

TEST_F(HttpTest, http_client_redirect_plain_to_plain_same_server_complex_url)
{
  HttpServer plain_server("plain1", Protocol::Plain, 1338);

  std::string body(4 * 8192, 'x');

  plain_server.add_redirect(
    "/foo",
    "http://127.0.0.1:1338/github-production-release-asset-2e65be/192349/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=XXXXXXXXXXXXXXXXXXXX%2F20230722%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230722T171852Z&X-Amz-Expires=300&X-Amz-Signature=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=192349&response-content-disposition=attachment%3B%20filename%3Dworkrave-windows-1.11.0-beta.6.exe&response-content-type=application%2Foctet-stream");
  plain_server.add(
    "/github-production-release-asset-2e65be/192349/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=XXXXXXXXXXXXXXXXXXXX%2F20230722%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230722T171852Z&X-Amz-Expires=300&X-Amz-Signature=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=192349&response-content-disposition=attachment%3B%20filename%3Dworkrave-windows-1.11.0-beta.6.exe&response-content-type=application%2Foctet-stream",
    body);
  plain_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();

  auto rc = get_sync(http, "http://127.0.0.1:1338/foo");

  EXPECT_EQ(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
    }
  plain_server.stop();
}

TEST_F(HttpTest, http_client_redirect_malformed)
{
  HttpServer plain_server("plain1", Protocol::Plain, 1338);

  std::string body(4 * 8192, 'x');

  plain_server.add_redirect("/foo", "x//300.1:1.1:1337:foo:/bar");
  plain_server.add("/bar", body);
  plain_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();

  auto rc = get_sync(http, "http://127.0.0.1:1338/foo");

  EXPECT_EQ(rc.has_error(), true);
  EXPECT_EQ(rc.error(), HttpClientErrc::InvalidRedirect);

  plain_server.stop();
}

TEST_F(HttpTest, http_client_redirect_empty)
{
  HttpServer plain_server("plain1", Protocol::Plain, 1338);

  std::string body(4 * 8192, 'x');

  plain_server.add_redirect("/foo", "");
  plain_server.add("/bar", body);
  plain_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();

  auto rc = get_sync(http, "http://127.0.0.1:1338/foo");

  EXPECT_EQ(rc.has_error(), true);
  EXPECT_EQ(rc.error(), HttpClientErrc::InvalidRedirect);

  plain_server.stop();
}

TEST_F(HttpTest, http_client_redirect_exceed_max)
{
  HttpServer plain_server(Protocol::Plain, 1338);

  plain_server.add_redirect("/a", "/b");
  plain_server.add_redirect("/b", "/c");
  plain_server.add_redirect("/c", "/d");
  plain_server.add_redirect("/d", "/e");
  plain_server.add_redirect("/e", "/f");
  plain_server.add_redirect("/f", "/g");
  plain_server.add("/g", "hello");
  plain_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);
  options.set_max_redirects(5);

  auto rc = get_sync(http, "http://127.0.0.1:1338/a");

  EXPECT_EQ(rc.has_error(), true);
  EXPECT_EQ(rc.error(), HttpClientErrc::TooManyRedirects);

  plain_server.stop();
}

TEST_F(HttpTest, http_client_redirect_below_max)
{
  HttpServer plain_server(Protocol::Plain, 1338);

  plain_server.add_redirect("/a", "/b");
  plain_server.add_redirect("/b", "/c");
  plain_server.add_redirect("/c", "/d");
  plain_server.add_redirect("/d", "/e");
  plain_server.add_redirect("/e", "/f");
  plain_server.add_redirect("/f", "/g");
  plain_server.add("/g", "hello");
  plain_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);
  options.set_max_redirects(7);

  auto rc = get_sync(http, "http://127.0.0.1:1338/a");

  EXPECT_EQ(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
    }

  plain_server.stop();
}

TEST_F(HttpTest, http_client_redirect_diabled)
{
  HttpServer plain_server(Protocol::Plain, 1338);

  plain_server.add_redirect("/a", "/b");
  plain_server.add("/b", "hello");
  plain_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);
  options.set_follow_redirects(false);

  auto rc = get_sync(http, "http://127.0.0.1:1338/a");

  EXPECT_EQ(rc.has_error(), true);
  EXPECT_EQ(rc.error(), HttpClientErrc::TooManyRedirects);

  plain_server.stop();
}

TEST_F(HttpTest, http_client_proxy_get_plain)
{
  HttpServer proxy_server("proxy", Protocol::Plain, 1338);
  HttpServer plain_server("http", Protocol::Plain, 1339);

  proxy_server.run();

  plain_server.run();
  plain_server.add("/foo", "foo\n");

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);
  options.set_proxy(unfold::http::Options::ProxyType::Custom);
  options.set_custom_proxy("http://127.0.0.1:1338");

  auto rc = get_sync(http, "http://127.0.0.1:1339/foo");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "foo\n");
    }

  plain_server.stop();
  proxy_server.stop();
}

TEST_F(HttpTest, http_client_proxy_get_plain_special_character)
{
  HttpServer proxy_server("proxy", Protocol::Plain, 1338);
  HttpServer plain_server("http", Protocol::Plain, 1339);

  proxy_server.run();

  plain_server.run();
  plain_server.add("/foo?x=%2f&b=2&c=3", "foo\n");

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);
  options.set_proxy(unfold::http::Options::ProxyType::Custom);
  options.set_custom_proxy("http://127.0.0.1:1338");

  auto rc = get_sync(http, "http://127.0.0.1:1339/foo?x=%2f&b=2&c=3");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "foo\n");
    }

  plain_server.stop();
  proxy_server.stop();
}

TEST_F(HttpTest, http_client_proxy_get_secure)
{
  HttpServer proxy_server(Protocol::Plain, 1338);
  HttpServer secure_server;

  proxy_server.run();

  secure_server.add("/foo", "foo\n");
  secure_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);
  options.set_proxy(unfold::http::Options::ProxyType::Custom);
  options.set_custom_proxy("http://127.0.0.1:1338");

  auto rc = get_sync(http, "https://127.0.0.1:1337/foo");

  EXPECT_EQ(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      EXPECT_EQ(result, 200);
      EXPECT_EQ(content, "foo\n");
    }

  proxy_server.stop();
  secure_server.stop();
}

TEST_F(HttpTest, http_client_proxy_not_found)
{
  HttpServer proxy_server(Protocol::Plain, 1338);
  HttpServer secure_server;

  proxy_server.run();

  secure_server.add("/foo", "foo\n");
  secure_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);
  options.set_proxy(unfold::http::Options::ProxyType::Custom);
  options.set_custom_proxy("http://127.0.0.1:3338");

  auto rc = get_sync(http, "https://127.0.0.1:1337/foo");

  EXPECT_EQ(rc.has_error(), true);
  EXPECT_EQ(rc.error(), HttpClientErrc::ConnectionRefused);
  proxy_server.stop();
  secure_server.stop();
}

TEST_F(HttpTest, http_client_invalid_cert)
{
  HttpServer server;
  server.add("/foo", "foo\n");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert("hello world");

  auto rc = get_sync(http, "https://127.0.0.1:1337/foo");

  EXPECT_EQ(rc.has_error(), true);
  EXPECT_EQ(rc.error(), HttpClientErrc::InvalidCertificate);

  server.stop();
}
