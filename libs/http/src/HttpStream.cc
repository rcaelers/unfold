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
  auto url_rc = parse_url(url_str);
  if (!url_rc)
    {
      co_return url_rc.as_failure();
    }
  requested_url = url_rc.value();

  outcome::std_result<HttpStream::response_t> response_rc = outcome::success();
  while (true)
    {
      if (connect_required())
        {
          auto rc = co_await connect();
          if (!rc)
            {
              co_return rc.as_failure();
            }

          if (is_tls_connection() && connected_url)
            {
              rc = co_await encrypt_connection(*connected_url);
              if (!rc)
                {
                  co_return rc.as_failure();
                }
            }

          rc = co_await proxy_connection();
          if (!rc)
            {
              co_return rc.as_failure();
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
      logger->info("executing redirecting to {}", requested_url.c_str());
    }

  co_await shutdown();
  co_return response_rc;
}

boost::asio::awaitable<outcome::std_result<HttpStream::response_t>>
HttpStream::send_receive_request(std::string filename, ProgressCallback cb)
{
  if (is_tls_connection() || is_tls_requested())
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

outcome::std_result<boost::urls::url>
HttpStream::parse_url(const std::string &u)
{
  auto url_rc = boost::urls::parse_uri(u);

  if (!url_rc)
    {
      logger->error("malformed URL '{}' ({})", u, url_rc.error());
      return HttpClientErrc::MalformedURL;
    }
  boost::urls::url url = url_rc.value();

  if (url.port().empty())
    {
      url.set_port(url.scheme() == "https" ? "443" : "80");
    }

  logger->debug("parsed URL {}", url.c_str());
  return url;
}

boost::urls::url
HttpStream::get_connect_url()
{
  auto proxy_url = options.get_proxy();

  if (proxy_url)
    {
      auto rc = parse_url(*proxy_url);
      if (rc)
        {
          return rc.value();
        }
    }
  return requested_url;
}

bool
HttpStream::connect_required()
{
  auto url = get_connect_url();
  return !connected_url || url.host() != (*connected_url).host() || url.port() != (*connected_url).port()
         || url.scheme() != (*connected_url).scheme();
}

boost::asio::awaitable<outcome::std_result<void>>
HttpStream::connect()
{
  auto url = get_connect_url();
  connected_url.reset();

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

  boost::beast::get_lowest_layer(*plain_stream).expires_after(options.get_timeout());
  co_await boost::beast::get_lowest_layer(*plain_stream)
    .async_connect(results, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to connect to '{}:{}' ({})", url.host(), url.port(), ec.message());
      co_return HttpClientErrc::ConnectionRefused;
    }
  connected_url = url;
  co_return outcome::success();
}

boost::asio::awaitable<outcome::std_result<void>>
HttpStream::encrypt_connection(boost::urls::url url)
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

  boost::beast::get_lowest_layer(*secure_stream).expires_after(options.get_timeout());
  co_await secure_stream->async_handshake(boost::asio::ssl::stream_base::client,
                                          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to perform TLS handshake with '{}' ({})", url.host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  co_return outcome::success();
}

boost::asio::awaitable<outcome::std_result<void>>
HttpStream::proxy_connection()
{
  if (is_tls_connection())
    {
      co_return co_await proxy_connection(secure_stream);
    }
  co_return co_await proxy_connection(plain_stream);
}

template<typename StreamType>
boost::asio::awaitable<outcome::std_result<void>>
HttpStream::proxy_connection(StreamType stream)
{
  auto proxy = options.get_proxy();

  if (!proxy || !is_tls_requested())
    {
      co_return outcome::success();
    }

  constexpr auto http_version = 11;
  auto target = requested_url.host() + std::string(":") + std::string(requested_url.port());
  boost::beast::http::request<boost::beast::http::string_body> req;
  req.method(boost::beast::http::verb::connect);
  req.target(target);
  req.keep_alive(true);
  req.version(http_version);
  req.set(boost::beast::http::field::host, connected_url->host());
  req.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);
  req.prepare_payload();

  boost::system::error_code ec;

  boost::beast::get_lowest_layer(*stream).expires_after(options.get_timeout());
  co_await boost::beast::http::async_write(*stream, req, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to send HTTP connect request to '{}' ({})", connected_url->host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  boost::beast::flat_buffer buffer;
  boost::beast::http::response_parser<boost::beast::http::empty_body> header_parser;
  header_parser.skip(true);

  buffer.max_size(16384);
  co_await boost::beast::http::async_read_header(*stream,
                                                 buffer,
                                                 header_parser,
                                                 boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to read HTTP header from {} ({})", connected_url->host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  if (boost::beast::http::to_status_class(header_parser.get().result()) != boost::beast::http::status_class::successful)
    {
      logger->error("failed to proxy to {} ({})", connected_url->host(), header_parser.get().result_int());
      co_return HttpClientErrc::CommunicationError;
    }

  if (is_tls_requested())
    {
      auto rc = co_await encrypt_connection(requested_url);
      if (!rc)
        {
          co_return rc.as_failure();
        }
    }
  co_return outcome::success();
}

boost::beast::http::request<boost::beast::http::string_body>
HttpStream::create_request()
{
  std::string target;
  auto proxy = options.get_proxy();

  if (proxy && !is_tls_requested())
    {
      logger->debug("using http via proxy {}", *proxy);
      target = requested_url.c_str();
    }
  else
    {
      target = requested_url.encoded_resource();
    }

  logger->debug("target {}", target);
  constexpr auto http_version = 11;
  boost::beast::http::request<boost::beast::http::string_body> req;
  req.method(boost::beast::http::verb::get);
  req.target(target);
  req.version(http_version);
  req.set(boost::beast::http::field::host, requested_url.host());
  req.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);
  req.prepare_payload();

  logger->debug("req HTTP/{} {}", req.version(), req.target());
  for (auto const &field: req)
    {
      logger->debug("req {}: {}", field.name_string(), field.value());
    }

  return req;
}

template<typename StreamType>
boost::asio::awaitable<outcome::std_result<void>>
HttpStream::send_request(StreamType stream, request_t request)
{
  boost::system::error_code ec;

  boost::beast::get_lowest_layer(*stream).expires_after(options.get_timeout());
  co_await boost::beast::http::async_write(*stream, request, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec)
    {
      logger->error("failed to send HTTP request to '{}' ({})", connected_url->host(), ec.message());
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
      logger->error("failed to read HTTP response from {} ({})", connected_url->host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  logger->debug("resp HTTP/{}", parser.get().version());
  for (auto const &field: parser.get())
    {
      logger->debug("resp {}: {}", field.name_string(), field.value());
    }
  logger->debug("resp body {}", parser.get().body());

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
      logger->error("failed to read HTTP header from {} ({})", connected_url->host(), ec.message());
      co_return HttpClientErrc::CommunicationError;
    }

  logger->debug("resp HTTP/{}", header_parser.get().version());
  for (auto const &field: header_parser.get())
    {
      logger->debug("resp {}: {}", field.name_string(), field.value());
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
          logger->error("failed to read HTTP file response from {} ({})", connected_url->host(), ec.message());
          co_return HttpClientErrc::CommunicationError;
        }
      logger->debug("resp {}", string_parser.get().body());
      co_return string_parser.get();
    }

  boost::beast::http::response_parser<boost::beast::http::file_body> parser{std::move(header_parser)};
  parser.get().body().open(filename.c_str(), boost::beast::file_mode::write, ec);
  if (ec)
    {
      logger->error("failed to open file '{}' for writing ({})", filename, ec.message());
      co_return HttpClientErrc::FileError;
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
          logger->error("failed to read HTTP file response from {} ({})", connected_url->host(), ec.message());
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
  if (redirect_count > options.get_max_redirects() || !options.get_follow_redirects())
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
          logger->error("no Location header in redirect response from {}", connected_url->host());
          return HttpClientErrc::InvalidRedirect;
        }

      logger->debug("redirecting to {}", redirect_url);
      if (redirect_url[0] == '/')
        {
          requested_url.set_path(redirect_url);
        }
      else
        {
          auto url_rc = parse_url(redirect_url);
          if (!url_rc)
            {
              logger->error("malformed redirect URL '{}'", redirect_url);
              return HttpClientErrc::InvalidRedirect;
            }
          logger->debug("redirecting to url {}", url_rc.value().c_str());
          requested_url = std::move(url_rc.value());
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
      boost::beast::get_lowest_layer(*stream).expires_after(options.get_timeout());
      co_await stream->async_shutdown(boost::asio::use_awaitable);
    }
  catch (std::exception &e)
    {
      // Skip eof
    }
}

template<>
boost::asio::awaitable<void>
HttpStream::shutdown_impl<std::shared_ptr<HttpStream::plain_stream_t>>(std::shared_ptr<plain_stream_t> stream)
{
  try
    {
      boost::beast::get_lowest_layer(*stream).expires_after(options.get_timeout());
      boost::system::error_code rc;

      stream->socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, rc);
      stream->socket().close(rc);
    }
  catch (std::exception &e)
    {
      // Skip eof
    }
  co_return;
}

boost::asio::awaitable<void>
HttpStream::shutdown()
{
  if (is_tls_connection())
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
HttpStream::is_tls_connection()
{
  return connected_url && connected_url->scheme() == "https";
}

bool
HttpStream::is_tls_requested()
{
  return connected_url && requested_url.scheme() == "https";
}
