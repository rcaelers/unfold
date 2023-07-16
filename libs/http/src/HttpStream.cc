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

#include <algorithm>
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

boost::asio::awaitable<outcome::std_result<HttpStream::response_t>>
HttpStream::execute(std::string url_str, std::string filename, ProgressCallback cb)
{
  auto rc = parse_url(url_str);
  if (!rc)
    {
      co_return rc.as_failure();
    }

  outcome::std_result<HttpStream::response_t> response_rc = outcome::success();
  while (true)
    {
      if (connect_required())
        {
          rc = co_await connect();
          if (!rc)
            {
              co_return rc.as_failure();
            }

          if (is_tls())
            {
              rc = co_await encrypt_connection();
              if (!rc)
                {
                  co_return rc.as_failure();
                }
            }
        }

      response_rc = co_await send_receive_request(filename, cb);
      if (!response_rc)
        {
          co_return response_rc.as_failure();
        }

      auto redirect_rc = handle_redirect(response_rc.value());
      if (!redirect_rc)
        {
          co_return redirect_rc.as_failure();
        }

      if (!redirect_rc.value())
        {
          break;
        }
    }

  co_await shutdown();
  co_return response_rc;
}

boost::asio::awaitable<outcome::std_result<HttpStream::response_t>>
HttpStream::send_receive_request(std::string filename, ProgressCallback cb)
{
  if (is_tls())
    {
      co_return co_await send_receive_request(secure_stream, filename, cb);
    }
  co_return co_await send_receive_request(plain_stream, filename, cb);
}

template<typename StreamType>
boost::asio::awaitable<outcome::std_result<HttpStream::response_t>>
HttpStream::send_receive_request(StreamType stream, std::string filename, ProgressCallback cb)
{
  auto request = create_request();

  outcome::std_result<HttpStream::response_t> response_rc = outcome::success();

  auto request_rc = co_await send_request(stream, request);
  if (!request_rc)
    {
      co_return request_rc.as_failure();
    }

  if (filename.empty())
    {
      response_rc = co_await receive_response_body(stream);
    }
  else
    {
      response_rc = co_await receive_response_body_as_file(stream, filename, cb);
    }

  if (!response_rc)
    {
      co_return response_rc.as_failure();
    }

  co_return response_rc.value();
}

outcome::std_result<void>
HttpStream::parse_url(const std::string &u)
{
  auto url_rc = boost::urls::parse_uri(u);

  if (!url_rc)
    {
      logger->error("malformed URL '{}' ({})", u, url_rc.error());
      return HttpClientErrc::MalformedURL;
    }
  url = url_rc.value();

  if (url.port().empty())
    {
      url.set_port(is_tls() ? "443" : "80");
    }

  return outcome::success();
}

bool
HttpStream::connect_required()
{
  return !current_url || url.host() != (*current_url).host() || url.port() != (*current_url).port()
         || url.scheme() != (*current_url).scheme();
}

boost::asio::awaitable<outcome::std_result<void>>
HttpStream::connect()
{
  current_url = url;

  auto executor = co_await boost::asio::this_coro::executor;
  plain_stream = std::make_shared<boost::beast::tcp_stream>(executor);

  boost::system::error_code ec;
  boost::asio::ip::tcp::resolver resolver(co_await boost::asio::this_coro::executor);
  auto results = co_await resolver.async_resolve(url.host(),
                                                 url.port(),
                                                 boost::asio::redirect_error(boost::asio::use_awaitable, ec));

  if (ec)
    {
      logger->error("failed to resolve hostname '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::NameResolutionFailed;
    }

  boost::beast::get_lowest_layer(*plain_stream).expires_after(TIMEOUT);
  co_await boost::beast::get_lowest_layer(*plain_stream)
    .async_connect(results, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to connect to '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::ConnectionRefused;
    }

  co_return outcome::success();
}

boost::asio::awaitable<outcome::std_result<void>>
HttpStream::encrypt_connection()
{
  secure_stream = std::make_shared<boost::beast::ssl_stream<boost::beast::tcp_stream>>(plain_stream->release_socket(), ctx);
  auto rc = init_certificates();
  if (!rc)
    {
      co_return rc.as_failure();
    }

  if (!SSL_set_tlsext_host_name(secure_stream->native_handle(), url.host().data()))
    {
      logger->error("failed to set TLS hostname");
      co_return HttpClientErrc::InternalError;
    }

  boost::system::error_code ec;

  boost::beast::get_lowest_layer(*secure_stream).expires_after(TIMEOUT);
  co_await secure_stream->async_handshake(boost::asio::ssl::stream_base::client,
                                          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to perform TLS handshake with '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }
  co_return outcome::success();
}

boost::beast::http::request<boost::beast::http::string_body>
HttpStream::create_request()
{
  constexpr auto http_version = 11;
  boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::get,
                                                                   url.encoded_path(),
                                                                   http_version};
  req.set(boost::beast::http::field::host, url.host());
  req.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);
  req.prepare_payload();
  req.keep_alive(true);

  return req;
}

template<typename StreamType>
boost::asio::awaitable<outcome::std_result<void>>
HttpStream::send_request(StreamType stream, request_t request)
{
  boost::system::error_code ec;

  boost::beast::get_lowest_layer(*stream).expires_after(TIMEOUT);
  co_await boost::beast::http::async_write(*stream, request, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to send HTTP request to '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  co_return outcome::success();
}

template<typename StreamType>
boost::asio::awaitable<outcome::std_result<HttpStream::response_t>>
HttpStream::receive_response_body(StreamType stream)
{
  boost::system::error_code ec;
  boost::beast::flat_buffer buffer;
  boost::beast::http::response_parser<boost::beast::http::string_body> parser;

  co_await boost::beast::http::async_read(*stream, buffer, parser, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to read HTTP response from {} ({})", url.host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }
  co_return parser.get();
}

template<typename StreamType>
boost::asio::awaitable<outcome::std_result<HttpStream::response_t>>
HttpStream::receive_response_body_as_file(StreamType stream, std::string filename, ProgressCallback cb)
{
  boost::system::error_code ec;
  boost::beast::flat_buffer buffer;
  boost::beast::http::response_parser<boost::beast::http::empty_body> header_parser;

  buffer.max_size(16384);
  co_await boost::beast::http::async_read_header(*stream,
                                                 buffer,
                                                 header_parser,
                                                 boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to read HTTP header from {} ({})", url.host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  if (boost::beast::http::to_status_class(header_parser.get().result()) != boost::beast::http::status_class::successful)
    {
      boost::beast::http::response_parser<boost::beast::http::string_body> string_parser{std::move(header_parser)};
      co_await boost::beast::http::async_read(*stream,
                                              buffer,
                                              string_parser,
                                              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec)
        {
          logger->error("failed to read HTTP file response from {} ({})", url.host(), ec.message());
          co_return HttpClientErrc::CommunicationError;
        }
      co_return string_parser.get();
    }

  boost::beast::http::response_parser<boost::beast::http::file_body> parser{std::move(header_parser)};
  parser.get().body().open(filename.c_str(), boost::beast::file_mode::write, ec);
  if (ec)
    {
      logger->error("failed to open file '{}' for writing ({})", filename, ec.message());
      co_return HttpClientErrc::InternalError;
    }

  size_t payload_size = 0;
  if (parser.content_length())
    {
      payload_size = *parser.content_length();
    }

  parser.body_limit((std::numeric_limits<std::uint64_t>::max)());
  cb(0);

  buffer.max_size(8192);
  while (!parser.is_done())
    {
      co_await boost::beast::http::async_read_some(*stream,
                                                   buffer,
                                                   parser,
                                                   boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec == boost::beast::http::error::need_buffer)
        {
          ec = {};
        }
      if (ec)
        {
          logger->error("failed to read HTTP file response from {} ({})", url.host(), ec.message());
          co_return HttpClientErrc::CommunicationError;
        }

      if (payload_size != 0 && parser.content_length_remaining())
        {
          double progress = static_cast<double>(payload_size - *parser.content_length_remaining())
                            / static_cast<double>(payload_size);
          cb(progress);
        }
    }
  cb(1.0);

  boost::beast::http::response<boost::beast::http::string_body> string_response{std::move(parser.get())};
  co_return string_response;
}

outcome::std_result<bool>
HttpStream::handle_redirect(response_t response)
{
  redirect_count++;
  if (redirect_count > options.get_max_redirects())
    {
      logger->error("too many redirects");
      return HttpClientErrc::TooManyRedirects;
    }

  if (boost::beast::http::to_status_class(response.result()) == boost::beast::http::status_class::successful)
    {
      redirect_count = 0;
      return false;
    }

  if (is_redirect(response.result()) && options.get_follow_redirects())
    {
      std::string redirect_url = response.base()["Location"];

      if (redirect_url.empty())
        {
          logger->error("no Location header in redirect response from {}", url.host());
          return HttpClientErrc::CommunicationError;
        }

      if (redirect_url[0] == '/')
        {
          url.set_path(redirect_url);
        }
      else
        {
          auto url_rc = parse_url(redirect_url);
          if (!url_rc)
            {
              logger->error("malformed redirect URL '{}'", redirect_url);
              return HttpClientErrc::MalformedURL;
            }
        }
      return true;
    }
  return false;
}

template<>
boost::asio::awaitable<void>
HttpStream::shutdown_impl<std::shared_ptr<HttpStream::secure_stream_t>>(std::shared_ptr<secure_stream_t> stream)
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

template<>
boost::asio::awaitable<void>
HttpStream::shutdown_impl<std::shared_ptr<HttpStream::plain_stream_t>>(std::shared_ptr<plain_stream_t> stream)
{
  try
    {
      boost::beast::get_lowest_layer(*stream).expires_after(TIMEOUT);
      boost::system::error_code rc;

      stream->socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, rc);
      stream->socket().close(rc);
    }
  catch (std::exception &e)
    {
      // Skip eof
      logger->error("failed to shutdown connection ({})", e.what());
    }
  co_return;
}

boost::asio::awaitable<void>
HttpStream::shutdown()
{
  if (is_tls())
    {
      co_return co_await shutdown_impl(secure_stream);
    }
  co_return co_await shutdown_impl(plain_stream);
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

bool
HttpStream::is_tls()
{
  return url.scheme() == "https";
}
