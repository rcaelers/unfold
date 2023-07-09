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

#include "http/Options.hh"
#include <exception>
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
#include "utils/Logging.hh"
#include "unfold/coro/IOContext.hh"

#include "unfold/coro/gtask.hh"

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
    const auto *log_file = "unfold-test-coro.log";

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
  Fixture()
    : context(g_main_context_new())
    , loop(g_main_loop_new(context, TRUE))
    , scheduler(context, io_context.get_io_context())
  {
  }

  ~Fixture()
  {
    g_main_loop_unref(loop);
    g_main_context_unref(context);
  }

  Fixture(const Fixture &) = delete;
  Fixture &operator=(const Fixture &) = delete;
  Fixture(Fixture &&) = delete;
  Fixture &operator=(Fixture &&) = delete;

  enum class SubTest
  {
    ThrowIntRet,
    ThrowVoidRet
  };

  unfold::coro::gtask<void> coro_test_throws_void();
  unfold::coro::gtask<int> coro_test_throws_int();
  unfold::coro::gtask<void> coro_test_throws_task(GMainLoop *loop, SubTest subtest);

  GMainContext *context = nullptr;
  GMainLoop *loop = nullptr;
  unfold::coro::IOContext io_context;
  unfold::coro::glib::scheduler scheduler;
  std::shared_ptr<spdlog::logger> logger{Logging::create("test")};
};

unfold::coro::gtask<int>
Fixture::coro_test_throws_int()
{
  co_await scheduler.sleep(100);
  throw std::runtime_error("error");
  co_return 1;
}

unfold::coro::gtask<void>
Fixture::coro_test_throws_void()
{
  co_await scheduler.sleep(100);
  throw std::runtime_error("error");
  co_return;
}

unfold::coro::gtask<void>
Fixture::coro_test_throws_task(GMainLoop *loop, SubTest subtest)
{
  try
    {
      switch (subtest)
        {
        case SubTest::ThrowIntRet:
          co_await coro_test_throws_int();
          break;
        case SubTest::ThrowVoidRet:
          co_await coro_test_throws_void();
          break;
        }
      BOOST_CHECK(false);
    }
  catch (std::exception &e)
    {
      BOOST_CHECK_EQUAL(e.what(), "error");
    }
  g_main_loop_quit(loop);
  co_return;
}

BOOST_TEST_GLOBAL_FIXTURE(GlobalFixture);

BOOST_FIXTURE_TEST_SUITE(unfold_coro_test, Fixture)

boost::asio::awaitable<outcome::std_result<std::string>>
download_appcast()
{
  Options options;
  options.add_ca_cert(cert);

  auto http = std::make_shared<unfold::http::HttpClient>(options);

  auto rc = co_await http->get("https://127.0.0.1:1337/foo");

  BOOST_CHECK_EQUAL(rc.has_error(), false);

  auto [result, content] = rc.value();

  BOOST_CHECK_EQUAL(result, 200);
  BOOST_CHECK_EQUAL(content, "foo\n");

  co_return content;
}

unfold::coro::gtask<int>
coro1_sub_task1()
{
  using namespace std::literals::chrono_literals;
  auto rc = co_await download_appcast();
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  auto content = rc.value();

  BOOST_CHECK_EQUAL(content, "foo\n");
  co_return 42;
}

unfold::coro::gtask<void>
coro1_sub_task2()
{
  co_return;
}

unfold::coro::gtask<void>
coro1_main_task(GMainLoop *loop)
{
  auto i = co_await coro1_sub_task1();
  BOOST_CHECK_EQUAL(i, 42);
  g_main_loop_quit(loop);
  co_return;
}

BOOST_AUTO_TEST_CASE(coro1)
{
  HttpServer server;
  server.add("/foo", "foo\n");
  server.run();

  unfold::coro::gtask<void> task = coro1_main_task(loop);
  scheduler.spawn(std::move(task));

  g_main_loop_run(loop);
  server.stop();
}

BOOST_AUTO_TEST_CASE(coro_test_throws_int)
{
  unfold::coro::gtask<void> task = coro_test_throws_task(loop, Fixture::SubTest::ThrowIntRet);
  scheduler.spawn(std::move(task));
  g_main_loop_run(loop);
}

BOOST_AUTO_TEST_CASE(coro_test_throws_void)
{
  unfold::coro::gtask<void> task = coro_test_throws_task(loop, Fixture::SubTest::ThrowVoidRet);
  scheduler.spawn(std::move(task));
  g_main_loop_run(loop);
}

BOOST_AUTO_TEST_SUITE_END()
