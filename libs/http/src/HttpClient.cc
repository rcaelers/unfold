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

#include "http/HttpClient.hh"

#include <array>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <iostream>
#include <fstream>
#include <exception>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/experimental/as_tuple.hpp>
#include "boost/outcome/outcome.hpp"
#include <boost/url/src.hpp>

#include "Connection.hh"
#include "http/HttpClientErrors.hh"

using namespace unfold::http;

HttpClient::HttpClient()
{
  ctx.set_default_verify_paths();
  ctx.set_verify_mode(boost::asio::ssl::verify_peer);
}

void
HttpClient::add_ca_cert(const std::string &cert)
{
  boost::system::error_code ec;
  ctx.add_certificate_authority(boost::asio::buffer(cert.data(), cert.size()), ec);
  if (ec)
    {
      logger->error("add_certificate_authority failed ({})", ec.message());
    }
}

outcome::std_result<Response>
HttpClient::get_sync(const std::string &url, std::ostream &file, ProgressCallback cb)
{
  boost::asio::io_context ioc;
  outcome::std_result<Response> ret = outcome::failure(HttpClientErrc::InternalError);
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          Connection conn(co_await boost::asio::this_coro::executor, std::ref(ctx));
          ret = co_await conn.get(url, file, cb);
          co_return;
        }
      catch (std::exception &e)
        {
          logger->error("get ostream failed {}", e.what());
        }
    },
    boost::asio::detached);
  ioc.run();
  ioc.restart();
  return ret;
}

outcome::std_result<Response>
HttpClient::get_sync(const std::string &url)
{
  boost::asio::io_context ioc;
  outcome::std_result<Response> ret = outcome::failure(HttpClientErrc::InternalError);

  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          Connection conn(co_await boost::asio::this_coro::executor, std::ref(ctx));
          ret = co_await conn.get(url);
          co_return;
        }
      catch (std::exception &e)
        {
          logger->error("get failed {}", e.what());
        }
    },
    boost::asio::detached);
  ioc.run();
  ioc.restart();
  return ret;
}

boost::asio::awaitable<outcome::std_result<Response>>
HttpClient::get(const std::string &url, std::ostream &file, ProgressCallback cb)
{
  auto executor = co_await boost::asio::this_coro::executor;
  Connection conn(executor, std::ref(ctx));
  auto r = co_await conn.get(url, file, cb);
  co_return Response{}; // r;
}

boost::asio::awaitable<outcome::std_result<Response>>
HttpClient::get(const std::string &url)
{
  auto executor = co_await boost::asio::this_coro::executor;
  Connection conn(executor, std::ref(ctx));
  auto r = co_await conn.get(url);
  co_return r;
}
