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

#include <boost/test/tools/old/interface.hpp>
#include <memory>
#include <fstream>

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

#define BOOST_TEST_MODULE "unfold"
#include <boost/test/unit_test.hpp>

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

    boost::asio::co_spawn(
      ioc,
      [&]() -> boost::asio::awaitable<void> { ret = co_await http->get(url); },
      boost::asio::detached);
    ioc.run();
    ioc.restart();
    return ret;
  }

private:
  std::shared_ptr<spdlog::logger> logger{Logging::create("test")};
};

BOOST_TEST_GLOBAL_FIXTURE(GlobalFixture);

BOOST_FIXTURE_TEST_SUITE(unfold_test, Fixture)

BOOST_AUTO_TEST_CASE(http_client_get_secure)
{
  HttpServer server;
  server.add("/foo", "foo\n");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://127.0.0.1:1337/foo");

  BOOST_CHECK_EQUAL(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      BOOST_CHECK_EQUAL(result, 200);
      BOOST_CHECK_EQUAL(content, "foo\n");
    }

  server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_get_plain)
{
  HttpServer server(Protocol::Plain);
  server.add("/foo", "foo\n");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "http://127.0.0.1:1337/foo");

  BOOST_CHECK_EQUAL(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      BOOST_CHECK_EQUAL(result, 200);
      BOOST_CHECK_EQUAL(content, "foo\n");
    }

  server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_not_found)
{
  HttpServer server;
  server.add("/foo", "foo\n");
  server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://127.0.0.1:1337/bar");

  BOOST_CHECK_EQUAL(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      BOOST_CHECK_EQUAL(result, 404);
      BOOST_CHECK_EQUAL(content, "The resource '/bar' was not found.");
    }
  server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_host_not_found)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://does-not-exist:1337/bar");
  BOOST_CHECK_EQUAL(rc.error(), HttpClientErrc::NameResolutionFailed);
}

BOOST_AUTO_TEST_CASE(http_client_connection_refused)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://127.0.0.1:1338/bar");
  BOOST_CHECK_EQUAL(rc.error(), HttpClientErrc::ConnectionRefused);
}

BOOST_AUTO_TEST_CASE(http_client_get_file_connection_refused)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://127.0.0.1:1338/foo", "foo.txt", [&](double progress) { BOOST_CHECK(false); });
  BOOST_CHECK_EQUAL(rc.error(), HttpClientErrc::ConnectionRefused);
}

BOOST_AUTO_TEST_CASE(http_client_invalid_ip_in_url)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "https://300.1.1.1:1337/bar");
  BOOST_CHECK_EQUAL(rc.error(), HttpClientErrc::NameResolutionFailed);
}

BOOST_AUTO_TEST_CASE(http_client_invalid_url)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "//300.1.1.1:1337:foo:/bar");
  BOOST_CHECK_EQUAL(rc.error(), HttpClientErrc::MalformedURL);
}

BOOST_AUTO_TEST_CASE(http_client_get_file_invalid_url)
{
  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);

  auto rc = get_sync(http, "//127.0.0.1:1337:1337/foo", "foo.txt", [&](double progress) { BOOST_CHECK(false); });
  BOOST_CHECK_EQUAL(rc.error(), HttpClientErrc::MalformedURL);
}

BOOST_AUTO_TEST_CASE(http_client_get_file)
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
    BOOST_CHECK_GE(progress, previous_progress);
    previous_progress = progress;
  });

  BOOST_CHECK_EQUAL(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();

      BOOST_CHECK_EQUAL(result, 200);
      BOOST_CHECK_GE(previous_progress + 0.0001, 1.0);
    }
  server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_get_file_not_found)
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
    BOOST_CHECK_GE(progress, previous_progress);
    previous_progress = progress;
  });

  BOOST_CHECK_EQUAL(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();

      BOOST_CHECK_EQUAL(result, 404);
      BOOST_CHECK_LE(previous_progress, 1);
    }
  server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_redirect_plain_to_secure)
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

  BOOST_CHECK_EQUAL(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      BOOST_CHECK_EQUAL(result, 200);
    }
  secure_server.stop();
  plain_server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_redirect_plain_to_plain_same_server)
{
  HttpServer plain_server("plain1", Protocol::Plain, 1338);

  std::string body(4 * 8192, 'x');

  plain_server.add_redirect("/foo", "/bar");
  plain_server.add("/bar", body);
  plain_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();

  auto rc = get_sync(http, "http://127.0.0.1:1338/foo");

  BOOST_CHECK_EQUAL(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      BOOST_CHECK_EQUAL(result, 200);
    }
  plain_server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_redirect_exceed_max)
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

  BOOST_CHECK_EQUAL(rc.has_error(), true);

  plain_server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_redirect_below_max)
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

  BOOST_CHECK_EQUAL(rc.has_error(), false);
  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      BOOST_CHECK_EQUAL(result, 200);
    }

  plain_server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_redirect_diabled)
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

  BOOST_CHECK_EQUAL(rc.has_error(), true);

  plain_server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_proxy_get_plain)
{
  HttpServer proxy_server("proxy", Protocol::Plain, 1338);
  HttpServer plain_server("http", Protocol::Plain, 1339);

  proxy_server.run();

  plain_server.run();
  plain_server.add("/foo", "foo\n");

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);
  options.set_proxy("http://127.0.0.1:1338");
  // options.set_proxy("http://127.0.0.1:8118");

  auto rc = get_sync(http, "http://127.0.0.1:1339/foo");

  BOOST_CHECK_EQUAL(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      BOOST_CHECK_EQUAL(result, 200);
      BOOST_CHECK_EQUAL(content, "foo\n");
    }

  plain_server.stop();
  proxy_server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_proxy_get_secure)
{
  HttpServer proxy_server(Protocol::Plain, 1338);
  HttpServer secure_server;

  proxy_server.run();

  secure_server.add("/foo", "foo\n");
  secure_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);
  options.set_proxy("http://127.0.0.1:1338");
  // options.set_proxy("http://127.0.0.1:8118");

  auto rc = get_sync(http, "https://127.0.0.1:1337/foo");

  BOOST_CHECK_EQUAL(rc.has_error(), false);

  if (!rc.has_error())
    {
      auto [result, content] = rc.value();
      BOOST_CHECK_EQUAL(result, 200);
      BOOST_CHECK_EQUAL(content, "foo\n");
    }

  proxy_server.stop();
  secure_server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_proxy_not_found)
{
  HttpServer proxy_server(Protocol::Plain, 1338);
  HttpServer secure_server;

  proxy_server.run();

  secure_server.add("/foo", "foo\n");
  secure_server.run();

  auto http = std::make_shared<unfold::http::HttpClient>();
  auto &options = http->options();
  options.add_ca_cert(cert);
  options.set_proxy("http://127.0.0.1:3338");
  // options.set_proxy("http://127.0.0.1:8118");

  auto rc = get_sync(http, "https://127.0.0.1:1337/foo");

  BOOST_CHECK_EQUAL(rc.has_error(), true);

  proxy_server.stop();
  secure_server.stop();
}

BOOST_AUTO_TEST_SUITE_END()
