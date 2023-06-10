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

#include "Connection.hh"

#include <array>
#include <exception>
#include <iostream>
#include <fstream>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>
#include <fmt/std.h>

#include <boost/url/parse.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/experimental/as_tuple.hpp>
#include <system_error>

#include "http/HttpClientErrors.hh"

#include <boost/outcome/result.hpp>

using namespace unfold::http;

Connection::Connection(boost::asio::any_io_executor exec_context, boost::asio::ssl::context &ctx)
  : stream(exec_context, ctx)
{
}

boost::asio::awaitable<outcome::std_result<Response>>
Connection::get(const std::string &url)
{
  outcome::std_result<void> rc{outcome::failure(HttpClientErrc::InternalError)};
  rc = parse_url(url);
  if (!rc)
    {
      co_return rc.as_failure();
    }
  rc = co_await send_request();
  if (!rc)
    {
      co_return rc.as_failure();
    }
  co_return co_await receive_reponse();
}

boost::asio::awaitable<outcome::std_result<Response>>
Connection::get(const std::string &url, std::ostream &file, ProgressCallback cb)
{
  outcome::std_result<void> rc{outcome::failure(HttpClientErrc::InternalError)};
  rc = parse_url(url);
  if (!rc)
    {
      co_return rc.as_failure();
    }

  rc = co_await send_request();
  if (!rc)
    {
      co_return rc.as_failure();
    }

  co_return co_await receive_reponse(file, cb);
}

boost::asio::awaitable<outcome::std_result<void>>
Connection::send_request()
{
  std::string port = !url.port().empty() ? url.port() : "443";

  if (!SSL_set_tlsext_host_name(stream.native_handle(), url.host().data()))
    {
      logger->error("failed to set TLS hostname");
      co_return HttpClientErrc::InternalError;
    }

  boost::system::error_code ec;
  boost::asio::ip::tcp::resolver resolver(co_await boost::asio::this_coro::executor);
  auto results = co_await resolver.async_resolve(url.host(), port, boost::asio::redirect_error(boost::asio::use_awaitable, ec));

  if (ec)
    {
      logger->error("failed to resolve hostname '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::NameResolutionFailed;
    }

  boost::beast::get_lowest_layer(stream).expires_after(TIMEOUT);
  co_await boost::beast::get_lowest_layer(stream).async_connect(results,
                                                                boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to connect to '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::ConnectionRefused;
    }

  boost::beast::get_lowest_layer(stream).expires_after(TIMEOUT);
  co_await stream.async_handshake(boost::asio::ssl::stream_base::client,
                                  boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to perform TLS handshake with '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  constexpr auto http_version = 11;
  boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::get,
                                                                   url.encoded_path(),
                                                                   http_version};
  req.set(boost::beast::http::field::host, url.host());
  req.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);

  boost::beast::get_lowest_layer(stream).expires_after(TIMEOUT);
  co_await boost::beast::http::async_write(stream, req, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to send HTTP request to '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  co_return outcome::success();
}

boost::asio::awaitable<outcome::std_result<Response>>
Connection::receive_reponse()
{
  boost::system::error_code ec;
  boost::beast::flat_buffer b;
  boost::beast::http::response<boost::beast::http::dynamic_body> res;

  co_await boost::beast::http::async_read(stream, b, res, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to read HTTP response from '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  co_await shutdown();
  auto x = std::make_pair(res.result_int(), boost::beast::buffers_to_string(res.body().data()));
  co_return x;
}

boost::asio::awaitable<outcome::std_result<Response>>
Connection::receive_reponse(std::ostream &file, ProgressCallback cb)
{
  Response ret;
  boost::system::error_code ec;
  boost::beast::flat_buffer buffer;
  boost::beast::http::response_parser<boost::beast::http::buffer_body> parser;

  parser.body_limit((std::numeric_limits<std::uint64_t>::max)());

  co_await boost::beast::http::async_read_header(stream,
                                                 buffer,
                                                 parser,
                                                 boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to read HTTP header from {} ({})", url.host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  if (parser.get().result() != boost::beast::http::status::ok)
    {
      boost::beast::http::response_parser<boost::beast::http::dynamic_body> p(std::move(parser));

      co_await boost::beast::http::async_read(stream, buffer, p, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec)
        {
          logger->error("failed to read HTTP response from {} ({})", url.host(), ec.message());
          co_return HttpClientErrc::CommunicationError;
        }
      co_await shutdown();
      co_return std::make_pair(p.get().result_int(), boost::beast::buffers_to_string(p.get().body().data()));
    }

  size_t payload_size = 0;
  if (parser.content_length())
    {
      payload_size = *parser.content_length();
    }

  while (!parser.is_done())
    {
      constexpr auto buffer_size = 1024;
      std::array<char, buffer_size> buf{};
      parser.get().body().data = buf.data();
      parser.get().body().size = buf.size();
      co_await boost::beast::http::async_read(stream,
                                              buffer,
                                              parser,
                                              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec == boost::beast::http::error::need_buffer)
        {
          ec = {};
        }
      if (ec)
        {
          logger->error("failed to read HTTP response from {} ({})", url.host(), ec.message());
          co_return HttpClientErrc::CommunicationError;
        }

      file.write(buf.data(), buf.size() - parser.get().body().size);
      if (payload_size != 0 && parser.content_length_remaining())
        {
          double progress = 1.0 * (payload_size - *parser.content_length_remaining()) / payload_size;
          cb(progress);
        }
    }

  ret = std::make_pair(parser.get().result_int(), "OK");

  co_await shutdown();
  co_return ret;
}

boost::asio::awaitable<void>
Connection::shutdown()
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

outcome::std_result<void>
Connection::parse_url(const std::string &u)
{
  auto r = boost::urls::parse_uri(u);

  if (r)
    {
      url = r.value();
    }
  else
    {
      logger->error("malformed URL '{}' ({})", u, r.error());
      return HttpClientErrc::MalformedURL;
    }
  return outcome::success();
}
