// Copyright (C) 2022, 2023 Rob Caelers <rob.caelers@gmail.com>
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

#include "http/HttpServer.hh"
#include "http/HttpClient.hh"

#include <spdlog/fmt/ostr.h>

#include <thread>
#include <string>
#include <fstream>
#include <streambuf>
#include <utility>

using namespace unfold::http;
using namespace unfold::http::detail;

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

  std::string const key =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDVr4sAS/gBsfur\n"
    "DLk6A9O+cZnaSH4zWvOXXmGRHSjgAQYMyVZ9sLVXn9Odmj+h6Qg0XMY4AzO/gATq\n"
    "F2voW1CtlPIcSa7eJPki3TD/UUn3ToYn11rfSaXjYB41FBCubp5y4S5Fg2GsWM1/\n"
    "5GYfLixzK2rM+DirEc05xjAqUWMtKFDXyD1O6KfOoeaq5qw5EojR9Ziu4K29cS6c\n"
    "9tze1Q4AXtVDdzNTypaC0RD+orNsZPQqIAfDfnAhwaJcsRlnGGf5iGe0jqJ+lThK\n"
    "sPO3x66nga66IqW1qe6OOs9MLAkZN92mXhS77qQeumi1hIYmUn3SEkydgQOzJTnl\n"
    "gmb8D9P1AgMBAAECggEBALifDZq5CFL2ovk7agGs8tJVNld5UMgwKcw7eFK3fexk\n"
    "FgUQI5E/Dr7hUSWW8qmCPFt5WK1mXtxy0Ews5keANelziedU5if6i+JKd53wbtak\n"
    "Wparo1DOQex8zDyR1IPRAUdCNQdMJySQKST5gh4od7Ed7w2e3N845zamfFDjtqt4\n"
    "2GJs3uASLWXSMzDls/baudjvEYXQVO6G2Ef65K43hRlsc3S0BA9o/WfTwKqB2QOU\n"
    "pDssy9Vsa7KwgDpr9i7MEga71LdyupNtL6W2dzxb1nxJTHobBpJf1AP914f2CXiC\n"
    "cSD/Sw1sYRbP9lzYFTbJ4w0phv/tzGYVSxAjrzG6/WECgYEA8O4RlTpgJg/D8+6i\n"
    "D7JO9jExdNkVbLvThB6y+zg59RUJ4r6iRA6VTl4nRMXvzBFhi169tnAaaS0hRCog\n"
    "QdMZutKC4U3fDgb5uCfLB76AwcH4vbIBcup2bcqNldbO60v1yBoBDTrOdr+xMnKk\n"
    "XdpiayiorfSRtYJVwzgbe5VleH0CgYEA4w04p+LVCv0xTeGIGn8FSeuzJJqwm4du\n"
    "7pK9llnSlEh5QvjBhsj7FQYLoyZ9a8FBd52Vujgx6hZwZ1XHr2nZAvpae+t8z+NC\n"
    "2rjfYUL/j14PaiMw3r+nBCBrVMRYZ0gAslpKOvAlBq20FAmCbfjswnc5tD8JiRn+\n"
    "X8oYIf8QGtkCgYA3mmn6a7eG8TqDEH7caoVosh+83ODh8FM3ebJK4kYV9t4KM37V\n"
    "gBwbMwWTDK90BErj1GCqOyMNRPoZdjNtnZ+hizXjc4pX/WoigySLS/8BOJgEh5Fo\n"
    "CQ599jJI84NbsHMv1DiL6hd+Nm1ZvDWM53qxSnfrdbcvEb5jSI6nLep2LQKBgQCe\n"
    "a5gvU86wJy9ils0fJ6dqB2HsVV6KdjnJjmtn325VdifdubFWOR8vcRNnl7CFIcdr\n"
    "DXHuB82T9mohP7HfS6xWLpY5xnpElt4LvFhoBZZI0ylQNhOgJ/sBnxkkgQbpsUyD\n"
    "JQqMCwjamxJ9tJDj6H5RxVxmzmD530AkV970wYHcKQKBgQCJe/4Cg6csOz92z9Bz\n"
    "ZFu+Y9vKmreNMj7BmScJRFPh0oniq3ce8QW/jZm2XPXRABnVFaHDdm9sz2RzDd9V\n"
    "oquu/RYK08vlEiw9LHhGoJgokD3JzfZkeVtalWfLlb00rdHdadBKJ4AQmbuzwuJT\n"
    "YxOnKqtodttRaqFyackJntJQsQ==\n"
    "-----END PRIVATE KEY-----\n";

  // openssl dhparam -out dh.pem 2048
  std::string const dh =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEA3Jy612FOsl7u5zhDNNKE/5FMhjyneZ4g9weeqfqbj1ZoX5gy3Lxt\n"
    "ELAWZqyHthNRoCcc3c9LiBBJw1H9XLdR7/nPd2aWxyyV6dw3j4/jdtaZEM0cVMhv\n"
    "nMwas8c3I4Rh+UKa3OwlIl5ZV5DPYFDLEdbQiAup6LU8csJMQk+laaX1tAm74uhu\n"
    "Wl+6PG5jSwvG/7bQl9LA7rtf+bhZd3PxZj7oZZ1A6csRJdEjfWRUJiaI6q8J66Rf\n"
    "g5ze43F6SKti62H96t0W1v8imHvRwJw+ZlhyMQJmsV+ME5+eskn/iTQb5cHMGuXl\n"
    "z6Ay0zXVTGVQboY5tIAq6HrFi5OuQ+q+AwIBAg==\n"
    "-----END DH PARAMETERS-----\n";

} // namespace

boost::asio::awaitable<void>
SecureSession::run()
{
  bool close = false;
  boost::beast::error_code ec;

  boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

  co_await stream.async_handshake(boost::asio::ssl::stream_base::server,
                                  boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("session handshake failed ({})", ec.message());
      co_return;
    }

  boost::beast::flat_buffer buffer;

  for (;;)
    {
      logger->debug("session read");
      boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

      co_await boost::beast::http::async_read(stream, buffer, req, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec == boost::beast::http::error::end_of_stream)
        {
          logger->debug("session eos");
          break;
        }
      if (ec)
        {
          logger->error("session read failed ({})", ec.message());
          co_return;
        }

      logger->debug("handle request");
      close = co_await handle_request(ec);
      if (ec)
        {
          logger->error("session write failed ({})", ec.message());
          co_return;
        }
      if (close)
        {
          logger->debug("closing session");
          break;
        }
    }

  boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
  co_await stream.async_shutdown(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("session shutdown failed ({})", ec.message());
    }
}

boost::asio::awaitable<void>
PlainSession::run()
{
  bool close = false;
  boost::beast::error_code ec;

  boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

  boost::beast::flat_buffer buffer;

  for (;;)
    {
      logger->debug("session read");
      boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
      co_await boost::beast::http::async_read(stream, buffer, req, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec == boost::beast::http::error::end_of_stream)
        {
          logger->debug("session eos");
          break;
        }
      if (ec)
        {
          logger->error("session read failed ({})", ec.message());
          co_return;
        }

      logger->debug("handle request");
      close = co_await handle_request(ec);
      if (ec)
        {
          logger->error("session write failed ({})", ec.message());
          co_return;
        }

      if (close)
        {
          logger->debug("closing session");
          break;
        }
    }
}

HttpServer::HttpServer(Protocol protocol, unsigned short port)
  : protocol(protocol)
  , port(port)
  , name(std::to_string(port))
{
}

HttpServer::HttpServer(const std::string &name, Protocol protocol, unsigned short port)
  : protocol(protocol)
  , port(port)
  , name(name)
{
}
boost::asio::awaitable<void>
HttpServer::do_listen(boost::asio::ip::tcp::endpoint endpoint)
{
  boost::beast::error_code ec;

  boost::asio::ip::tcp::acceptor acceptor(ioc);
  acceptor.open(endpoint.protocol(), ec);
  if (ec)
    {
      logger->error("acceptor open failed ({})", ec.message());
      co_return;
    }

  acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
  if (ec)
    {
      logger->error("acceptor set_option failed ({})", ec.message());
      co_return;
    }

  acceptor.bind(endpoint, ec);
  if (ec)
    {
      logger->error("acceptor bind failed ({})", ec.message());
      co_return;
    }

  acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
  if (ec)
    {
      logger->error("acceptor listen failed ({})", ec.message());
      co_return;
    }

  for (;;)
    {
      boost::asio::ip::tcp::socket socket(ioc);
      co_await acceptor.async_accept(socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec)
        {
          logger->error("acceptor accept failed ({})", ec.message());
          co_return;
        }

      if (protocol == Protocol::Secure)
        {
          boost::asio::co_spawn(
            ioc,
            [this, &socket]() -> boost::asio::awaitable<void> {
              SecureSession session(name, std::move(socket), ctx, ioc, documents, redirects);
              co_await session.run();
            },
            boost::asio::detached);
        }
      else
        {
          boost::asio::co_spawn(
            ioc,
            [this, &socket]() -> boost::asio::awaitable<void> {
              PlainSession session(name, std::move(socket), ioc, documents, redirects);
              co_await session.run();
            },
            boost::asio::detached);
        }
    }
}

void
HttpServer::run()
{
  auto address = boost::asio::ip::make_address("127.0.0.1");

  ctx.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2
                  | boost::asio::ssl::context::single_dh_use);

  ctx.use_certificate_chain(boost::asio::buffer(cert.data(), cert.size()));
  ctx.use_private_key(boost::asio::buffer(key.data(), key.size()), boost::asio::ssl::context::file_format::pem);
  ctx.use_tmp_dh(boost::asio::buffer(dh.data(), dh.size()));

  boost::asio::co_spawn(
    ioc,
    [=, this]() -> boost::asio::awaitable<void> {
      auto ep = boost::asio::ip::tcp::endpoint{address, port};
      co_await do_listen(ep);
    },
    boost::asio::detached);

  workers.reserve(threads);
  for (auto i = 0; i < threads; i++)
    {
      workers.emplace_back([this] { ioc.run(); });
    }
}

void
HttpServer::stop()
{
  if (!workers.empty())
    {
      ioc.stop();
      for (auto &w: workers)
        {
          w.join();
        }
      workers.clear();
    }
}

void
HttpServer::add(std::string_view file, const std::string &body)
{
  documents.add(file, body);
}

void
HttpServer::add_file(std::string_view file, const std::string &filename)
{
  std::ifstream f(filename.c_str(), std::ios::binary);
  std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  spdlog::debug("file {} {}", filename, content.size());
  add(file, content);
}

void
HttpServer::add_redirect(std::string_view from, std::string_view to)
{
  redirects.add(from, to);
}

void
Documents::add(std::string_view file, const std::string &body)
{
  content[file] = body;
}

bool
Documents::exists(std::string_view file) const
{
  return content.contains(std::string(file));
}

std::string
Documents::get(std::string_view file) const
{
  return content.at(file);
}

void
Redirects::add(std::string_view from, const std::string_view to)
{
  redirects[from] = to;
}

bool
Redirects::exists(std::string_view from) const
{
  return redirects.contains(std::string(from));
}

std::string_view
Redirects::get(std::string_view from) const
{
  return redirects.at(from);
}
