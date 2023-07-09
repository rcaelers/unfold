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

#include "http/HttpStream.hh"

#include <array>
#include <exception>
#include <iostream>
#include <fstream>
#include <sstream>
#include <system_error>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>
#include <fmt/std.h>

#include <boost/url/parse.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/experimental/as_tuple.hpp>
#include <boost/asio/spawn.hpp>

#include "http/HttpClientErrors.hh"
#include "http/Options.hh"

#include <boost/outcome/result.hpp>
#include <utility>

#if defined(WIN32)
#  include <wincrypt.h>
#endif

using namespace unfold::http;

HttpStream::HttpStream(Options options_)
  : options(std::move(options_))
{
#if defined(WIN32)
  add_windows_root_certs(ctx);
#else
  ctx.set_default_verify_paths();
#endif
  ctx.set_verify_mode(boost::asio::ssl::verify_peer);
}

boost::asio::awaitable<outcome::std_result<Response>>
HttpStream::execute(std::string url)
{
  std::stringstream ss;

  auto rc = co_await execute(url, ss, [](double) {});
  if (!rc)
    {
      co_return rc;
    }
  if (rc.value().first != 200)
    {
      co_return rc;
    }
  co_return std::make_pair(rc.value().first, ss.str());
}

boost::asio::awaitable<outcome::std_result<Response>>
HttpStream::execute(std::string url, std::ostream &file, ProgressCallback cb)
{
  outcome::std_result<void> rc{outcome::failure(HttpClientErrc::InternalError)};

  rc = init_certificates();
  if (!rc)
    {
      logger->error("invalid ca certificate ({})", rc.error().message());
      co_return rc.as_failure();
    }
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

  co_return co_await receive_response(file, cb);
}

boost::asio::awaitable<outcome::std_result<void>>
HttpStream::send_request()
{
  std::string port = !url.port().empty() ? url.port() : "443";

  auto executor = co_await boost::asio::this_coro::executor;
  stream = std::make_shared<boost::beast::ssl_stream<boost::beast::tcp_stream>>(executor, ctx);

  if (!SSL_set_tlsext_host_name(stream->native_handle(), url.host().data()))
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

  boost::beast::get_lowest_layer(*stream).expires_after(TIMEOUT);
  co_await boost::beast::get_lowest_layer(*stream).async_connect(results,
                                                                 boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to connect to '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::ConnectionRefused;
    }

  boost::beast::get_lowest_layer(*stream).expires_after(TIMEOUT);
  co_await stream->async_handshake(boost::asio::ssl::stream_base::client,
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

  boost::beast::get_lowest_layer(*stream).expires_after(TIMEOUT);
  co_await boost::beast::http::async_write(*stream, req, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to send HTTP request to '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  co_return outcome::success();
}

bool
HttpStream::is_redirect(auto code)
{
  return code == boost::beast::http::status::moved_permanently || code == boost::beast::http::status::found
         || code == boost::beast::http::status::see_other || code == boost::beast::http::status::temporary_redirect
         || code == boost::beast::http::status::permanent_redirect;
}

bool
HttpStream::is_ok(auto code)
{
  return code == boost::beast::http::status::ok;
}

boost::asio::awaitable<outcome::std_result<Response>>
HttpStream::receive_response(std::ostream &out, ProgressCallback cb)
{
  Response ret;
  boost::system::error_code ec;
  boost::beast::flat_buffer buffer;
  boost::beast::http::response_parser<boost::beast::http::buffer_body> parser;

  parser.body_limit((std::numeric_limits<std::uint64_t>::max)());

  co_await boost::beast::http::async_read_header(*stream,
                                                 buffer,
                                                 parser,
                                                 boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to read HTTP header from {} ({})", url.host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  if (is_redirect(parser.get().result()))
    {
      std::string redirect_url = parser.get().base()["Location"];
      if (redirect_url.empty())
        {
          logger->error("no Location header in redirect response from {}", url.host());
          co_return HttpClientErrc::CommunicationError;
        }
      co_return co_await execute(redirect_url);
    }

  if (!is_ok(parser.get().result()))
    {
      boost::beast::http::response_parser<boost::beast::http::dynamic_body> p(std::move(parser));

      co_await boost::beast::http::async_read(*stream, buffer, p, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
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
      co_await boost::beast::http::async_read(*stream,
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

      out.write(buf.data(), static_cast<std::streamsize>(buf.size() - parser.get().body().size));
      if (payload_size != 0 && parser.content_length_remaining())
        {
          double progress = static_cast<double>(payload_size - *parser.content_length_remaining())
                            / static_cast<double>(payload_size);
          cb(progress);
        }
    }

  ret = std::make_pair(parser.get().result_int(), "OK");

  co_await shutdown();
  co_return ret;
}

boost::asio::awaitable<void>
HttpStream::shutdown()
{
  try
    {
      boost::beast::get_lowest_layer(*stream).expires_after(TIMEOUT);
      co_await stream->async_shutdown(boost::asio::use_awaitable);
    }
  catch (std::exception &e)
    {
      // Skip eof
      logger->error("failed to shutdown connection ({})", e.what());
    }
}

outcome::std_result<void>
HttpStream::parse_url(const std::string &u)
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

outcome::std_result<void>
HttpStream::init_certificates()
{
  for (const auto &cert: options.get_ca_certs())
    {
      boost::system::error_code ec;
      ctx.add_certificate_authority(boost::asio::buffer(cert.data(), cert.size()), ec);
      if (ec)
        {
          logger->error("add_certificate_authority failed ({})", ec.message());
          return outcome::failure(unfold::http::HttpClientErrc::InvalidCertificate);
        }
    }
  return outcome::success();
}

#if defined(WIN32)
void
HttpStream::add_windows_root_certs(boost::asio::ssl::context &ctx)
{
  HCERTSTORE cert_store = CertOpenSystemStore(0, "ROOT");
  if (cert_store == nullptr)
    {
      logger->error("cannot open Windows cert store");
      return;
    }

  X509_STORE *store = X509_STORE_new();
  PCCERT_CONTEXT context = nullptr;
  while ((context = CertEnumCertificatesInStore(cert_store, context)) != nullptr)
    {
      auto *encoded_cert = const_cast<const unsigned char **>(&context->pbCertEncoded);
      auto encoded_cert_len = static_cast<long>(context->cbCertEncoded);
      X509 *x509 = d2i_X509(nullptr, encoded_cert, encoded_cert_len);
      if (x509 != nullptr)
        {
          X509_STORE_add_cert(store, x509);
          X509_free(x509);
        }
    }

  CertFreeCertificateContext(context);
  CertCloseStore(cert_store, 0);
  SSL_CTX_set_cert_store(ctx.native_handle(), store);
}
#endif
