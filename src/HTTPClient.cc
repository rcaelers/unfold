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

#include "HTTPClient.hh"

#include <array>
#include <stdexcept>
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

#include <boost/url/src.hpp>

// TODO: support http
// TODO: proper error handling/reporting

constexpr auto use_nothrow_awaitable = boost::asio::experimental::as_tuple(boost::asio::use_awaitable);

Request::Request(std::string url, boost::asio::io_context &ioc, boost::asio::ssl::context &ctx)
  : url(std::move(url))
  , ioc(ioc)
  , stream(ioc, ctx)
{
}

boost::asio::awaitable<Response>
Request::download(const std::string &filename, ProgressCallback cb)
{
  Response ret;
  co_await request();
  co_return co_await download_reponse(filename, cb);
}

boost::asio::awaitable<Response>
Request::get()
{
  Response ret;
  co_await request();
  co_return co_await receive_reponse();
}

boost::asio::awaitable<void>
Request::request()
{
  std::string host;
  std::string port;
  std::string path;

  try
    {
      boost::urls::url_view u = boost::urls::parse_uri(url).value();

      host = u.host();
      port = u.port();
      path = u.encoded_path();

      if (port.empty())
        {
          // TODO: http
          port = "443";
        }
    }
  catch (std::invalid_argument const &)
    {
      // TODO: handle error
    }

  if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
    {
      throw std::runtime_error("SSL_set_tlsext_host_name failed");
    }

  boost::asio::ip::tcp::resolver resolver(ioc);
  auto results = co_await resolver.async_resolve(host, port, boost::asio::use_awaitable);

  boost::beast::get_lowest_layer(stream).expires_after(TIMEOUT);

  co_await boost::beast::get_lowest_layer(stream).async_connect(results, boost::asio::use_awaitable);

  boost::beast::get_lowest_layer(stream).expires_after(TIMEOUT);

  co_await stream.async_handshake(boost::asio::ssl::stream_base::client, boost::asio::use_awaitable);

  constexpr auto http_version = 11;
  boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::get, path, http_version};
  req.set(boost::beast::http::field::host, host);
  req.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);

  boost::beast::get_lowest_layer(stream).expires_after(TIMEOUT);

  co_await boost::beast::http::async_write(stream, req, boost::asio::use_awaitable);
  co_return;
}

boost::asio::awaitable<Response>
Request::receive_reponse()
{
  boost::beast::flat_buffer b;
  boost::beast::http::response<boost::beast::http::dynamic_body> res;

  co_await boost::beast::http::async_read(stream, b, res, boost::asio::use_awaitable);
  co_return std::make_pair(res.result_int(), boost::beast::buffers_to_string(res.body().data()));
}

boost::asio::awaitable<Response>
Request::download_reponse(const std::string &filename, ProgressCallback cb)
{
  Response ret;
  boost::beast::flat_buffer buffer;
  boost::beast::http::response_parser<boost::beast::http::buffer_body> parser;

  co_await boost::beast::http::async_read_header(stream, buffer, parser, boost::asio::use_awaitable);

  if (parser.get().result() != boost::beast::http::status::ok)
    {
      boost::beast::http::response_parser<boost::beast::http::dynamic_body> p(std::move(parser));

      co_await boost::beast::http::async_read(stream, buffer, p, boost::asio::use_awaitable);
      co_return std::make_pair(p.get().result_int(), boost::beast::buffers_to_string(p.get().body().data()));
    }

  size_t payload_size = 0;
  if (parser.content_length())
    {
      payload_size = *parser.content_length();
    }

  std::ofstream out_file(filename.c_str(), std::ofstream::binary);

  while (!parser.is_done())
    {
      constexpr auto buffer_size = 1024;
      boost::beast::error_code ec;
      std::array<char, buffer_size> buf{};
      parser.get().body().data = buf.data();
      parser.get().body().size = buf.size();
      co_await boost::beast::http::async_read(stream, buffer, parser, use_nothrow_awaitable);
      if (ec == boost::beast::http::error::need_buffer)
        {
          logger->info("need buffer");
          ec = {};
        }
      if (!ec)
        {
          out_file.write(buf.data(), buf.size() - parser.get().body().size);
          if (payload_size != 0 && parser.content_length_remaining())
            {
              double progress = 1.0 * (payload_size - *parser.content_length_remaining()) / payload_size;
              cb(progress);
            }
        }
    }

  out_file.close();
  ret = std::make_pair(parser.get().result_int(), "OK");

  co_await shutdown();
  co_return ret;
}

boost::asio::awaitable<void>
Request::shutdown()
{
  try
    {
      boost::beast::get_lowest_layer(stream).expires_after(TIMEOUT);
      co_await stream.async_shutdown(boost::asio::use_awaitable);
    }
  catch (std::exception &e)
    {
      // Skip eof
      logger->error("failed to shutdown connection ({})", e.what());
    }
}

HTTPClient::HTTPClient()
{
  ctx.set_default_verify_paths();
  ctx.set_verify_mode(boost::asio::ssl::verify_peer);
}

void
HTTPClient::add_ca_cert(const std::string &cert)
{
  boost::system::error_code ec;
  ctx.add_certificate_authority(boost::asio::buffer(cert.data(), cert.size()), ec);
  if (ec)
    {
      logger->error("add_certificate_authority failed ({})", ec.message());
    }
}

Response
HTTPClient::download(const std::string &url, const std::string &filename, ProgressCallback cb)
{
  Response ret;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          Request request(url, std::ref(ioc), std::ref(ctx));
          ret = co_await request.download(filename, cb);
        }
      catch (std::exception &e)
        {
          logger->error("download failed {}", e.what());
        }
    },
    boost::asio::detached);
  ioc.run();
  return ret;
}

Response
HTTPClient::get(const std::string &url)
{
  Response ret;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          Request request(url, std::ref(ioc), std::ref(ctx));
          ret = co_await request.get();
        }
      catch (std::exception &e)
        {
          logger->error("get {}", e.what());
          throw;
        }
    },
    boost::asio::detached);
  ioc.run();
  return ret;
}
