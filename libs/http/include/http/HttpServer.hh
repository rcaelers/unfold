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

#ifndef NET_HTTP_SERVER_HH
#define NET_HTTP_SERVER_HH

#include <thread>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/config.hpp>
#include <boost/algorithm/string.hpp>

#include <string_view>
#include <array>
#include <map>

#include <spdlog/spdlog.h>

#include "utils/Logging.hh"
#include "http/HttpClient.hh"

namespace unfold::http
{
  namespace detail
  {
    class Documents
    {
    public:
      Documents() = default;

      void add(std::string_view file, const std::string &body);
      bool exists(std::string_view file) const;
      std::string get(std::string_view file) const;

    private:
      std::map<std::string_view, std::string> content;
    };

    class Redirects
    {
    public:
      Redirects() = default;

      void add(std::string_view from, std::string_view to);
      bool exists(std::string_view from) const;
      std::string_view get(std::string_view from) const;

    private:
      std::map<std::string_view, std::string_view> redirects;
    };

    template<typename StreamType>
    class Session
    {
    public:
      Session(const std::string &name,
              StreamType &&stream,
              boost::asio::io_context &ioc,
              Documents documents,
              detail::Redirects redirects)
        : stream(std::move(stream))
        , ioc(ioc)
        , documents(std::move(documents))
        , redirects(std::move(redirects))
      {
        logger = unfold::utils::Logging::create("test:server:session:" + name);
        http = std::make_shared<unfold::http::HttpClient>();
      }

      ~Session() = default;
      Session(const Session &) = delete;
      Session &operator=(const Session &) = delete;
      Session(Session &&) = delete;
      Session &operator=(Session &&) = delete;

    private:
      template<bool isRequest, class Body, class Fields>
      boost::asio::awaitable<bool> send(boost::beast::http::message<isRequest, Body, Fields> &&msg, boost::beast::error_code &ec)
      {
        auto eof = msg.need_eof();
        logger->info("send need eof: ({})", eof);
        boost::beast::http::serializer<isRequest, Body, Fields> sr{msg};
        co_await boost::beast::http::async_write(stream, sr, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        co_return eof;
      }

      std::string_view mime_type(std::string_view path)
      {
        auto pos = path.rfind(".");
        if (pos != std::string_view::npos)
          {
            auto ext = path.substr(pos);
            if (ext == ".xml")
              {
                return "application/xml";
              }
          }
        return "application/octet-stream";
      }

      boost::asio::awaitable<bool> send_status(boost::beast::http::status status, std::string text, boost::beast::error_code &ec)
      {
        boost::beast::http::response<boost::beast::http::string_body> res{status, req.version()};
        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(boost::beast::http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = text;
        res.prepare_payload();
        co_return co_await send(std::move(res), ec);
      }

      boost::asio::awaitable<bool> send_bad_request(std::string_view why, boost::beast::error_code &ec)
      {
        co_return co_await send_status(boost::beast::http::status::bad_request, std::string(why), ec);
      }

      boost::asio::awaitable<bool> send_not_found(std::string_view target, boost::beast::error_code &ec)
      {
        co_return co_await send_status(boost::beast::http::status::not_found,
                                       "The resource '" + std::string(target) + "' was not found.",
                                       ec);
      }

      boost::asio::awaitable<bool> send_redirect(const std::string_view location, boost::beast::error_code &ec)
      {
        boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::found, req.version()};
        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(boost::beast::http::field::location, location);
        res.keep_alive(req.keep_alive());
        res.prepare_payload();
        co_return co_await send(std::move(res), ec);
      }

    protected:
      boost::asio::awaitable<bool> handle_request(boost::beast::error_code &ec)
      {
        logger->debug("handle request: {}", req.target());
        if (req.method() == boost::beast::http::verb::connect)
          {
            co_return co_await handle_connect_request(ec);
          }
        if (req.method() == boost::beast::http::verb::get)
          {
            co_return co_await handle_get_request(ec);
          }
        logger->error("unknown http method: ({})", req.method_string());
        co_await send_bad_request("Unknown HTTP method", ec);
        co_return false;
      }

      boost::asio::awaitable<bool> handle_connect_request(boost::beast::error_code &ec)
      {
        logger->debug("handle connect request: {}", req.target());
        if (!req.keep_alive())
          {
            logger->error("connection must be keepalive");
            co_await send_bad_request("connection must be keepalive", ec);
          }

        auto const target = req.target();

        std::vector<std::string> target_parts;
        boost::algorithm::split(target_parts, target, boost::is_any_of(":"));
        if (target_parts.size() != 2)
          {
            logger->error("invalid target format: ({})", target);
            co_return co_await send_bad_request("Invalid target format", ec);
          }

        std::string host = target_parts[0];
        std::string port = target_parts[1];

        boost::asio::ip::tcp::resolver resolver(co_await boost::asio::this_coro::executor);
        const auto endpoints = co_await resolver.async_resolve(
          host,
          port,
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));

        if (ec)
          {
            logger->error("failed to resolve hostname '{}' ({})", host, ec.message());
            co_return true;
          }

        if (endpoints.empty())
          {
            logger->error("no endpoints found for hostname: ({})", host);
            co_return true;
          }

        boost::asio::ip::tcp::socket peer{ioc};
        co_await peer.async_connect(*(endpoints.begin()), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
          {
            logger->error("failed to connected to: ({}) {}", host, ec.message());
            co_await send_bad_request("Unable to establish connection with remote host", ec);
            co_return true;
          }
        co_await send_status(boost::beast::http::status::ok, "OK", ec);

        co_await boost::asio::experimental::make_parallel_group(
          boost::asio::co_spawn(
            ioc,
            [&]() -> boost::asio::awaitable<void> { co_await forward_data(stream, peer); },
            boost::asio::deferred),
          boost::asio::co_spawn(
            ioc,
            [&]() -> boost::asio::awaitable<void> { co_await forward_data(peer, stream); },
            boost::asio::deferred))
          .async_wait(boost::asio::experimental::wait_for_one(), boost::asio::deferred);
        co_return !req.keep_alive();
      }

      boost::asio::awaitable<bool> handle_proxied_get_request(boost::beast::error_code &ec)
      {
        logger->debug("handle proxy connect request: {}", req.target());
        auto rc = co_await http->get(req.target());
        if (!rc)
          {
            co_return co_await send_not_found(req.target(), ec);
          }

        auto [code, body] = rc.value();

        boost::beast::http::response<boost::beast::http::string_body> res{std::piecewise_construct,
                                                                          std::make_tuple(body),
                                                                          std::make_tuple(boost::beast::http::status::ok,
                                                                                          req.version())};
        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(boost::beast::http::field::content_type, mime_type(req.target()));
        res.content_length(body.size());
        res.keep_alive(req.keep_alive());
        co_return co_await send(std::move(res), ec);
      }

      boost::asio::awaitable<bool> handle_get_request(boost::beast::error_code &ec)
      {
        logger->debug("handle get request: {}", req.target());
        if (!req.target().starts_with("/"))
          {
            co_return co_await handle_proxied_get_request(ec);
          }

        if (redirects.exists(req.target()))
          {
            auto location = redirects.get(req.target());
            logger->info("redirecting to: ({})", location);
            co_return co_await send_redirect(location, ec);
          }

        if (documents.exists(req.target()))
          {
            logger->debug("sending document: {}", req.target());
            auto txt = documents.get(req.target());
            auto length = txt.size();

            boost::beast::http::response<boost::beast::http::string_body> res{std::piecewise_construct,
                                                                              std::make_tuple(std::move(txt)),
                                                                              std::make_tuple(boost::beast::http::status::ok,
                                                                                              req.version())};
            res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(boost::beast::http::field::content_type, mime_type(req.target()));
            res.content_length(length);
            res.keep_alive(req.keep_alive());
            co_return co_await send(std::move(res), ec);
          }

        logger->debug("sending not found document: {}", req.target());
        co_return co_await send_not_found(req.target(), ec);
      }

      template<typename StringFrom, typename StreamTo>
      boost::asio::awaitable<void> forward_data(StringFrom &in, StreamTo &out)
      {
        std::array<uint8_t, 2048> data{};
        boost::beast::error_code ec;

        for (;;)
          {
            size_t length = co_await in.async_read_some(boost::asio::buffer(data),
                                                        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec)
              {
                break;
              }
            co_await boost::asio::async_write(out,
                                              boost::asio::buffer(data, length),
                                              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec)
              {
                break;
              }
          }

        if (ec)
          {
            boost::beast::get_lowest_layer(in).close();
            boost::beast::get_lowest_layer(out).close();
          }
      }

    protected:
      StreamType stream;
      boost::beast::http::request<boost::beast::http::string_body> req;

    private:
      boost::asio::io_context &ioc;
      Documents documents;
      Redirects redirects;
      std::shared_ptr<http::HttpClient> http;
      std::shared_ptr<spdlog::logger> logger;
    };

    class PlainSession : public Session<boost::beast::tcp_stream>
    {
    public:
      PlainSession(const std::string &name,
                   boost::asio::ip::tcp::socket socket,
                   boost::asio::io_context &ioc,
                   Documents documents,
                   detail::Redirects redirects)
        : Session<boost::beast::tcp_stream>(name, boost::beast::tcp_stream(std::move(socket)), ioc, documents, redirects)
      {
        logger = unfold::utils::Logging::create(std::string("test:server:plainsession:") + name);
      }

      boost::asio::awaitable<void> run();

    private:
      std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("test:server:plainsession")};
    };

    class SecureSession : public Session<boost::beast::ssl_stream<boost::beast::tcp_stream>>
    {
    public:
      SecureSession(const std::string &name,
                    boost::asio::ip::tcp::socket socket,
                    boost::asio::ssl::context &ctx,
                    boost::asio::io_context &ioc,
                    Documents documents,
                    detail::Redirects redirects)
        : Session<boost::beast::ssl_stream<boost::beast::tcp_stream>>(name, {std::move(socket), ctx}, ioc, documents, redirects)
      {
        logger = unfold::utils::Logging::create(std::string("test:server:securesession:") + name);
      }

      boost::asio::awaitable<void> run();

    private:
      std::shared_ptr<spdlog::logger> logger;
    };
  } // namespace detail

  enum class Protocol
  {
    Plain,
    Secure
  };

  class HttpServer
  {
  public:
    explicit HttpServer(Protocol protocol = Protocol::Secure, unsigned short port = 1337);
    explicit HttpServer(const std::string &name, Protocol protocol = Protocol::Secure, unsigned short port = 1337);
    void run();
    void stop();

    void add(std::string_view file, const std::string &body);
    void add_file(std::string_view file, const std::string &filename);
    void add_redirect(std::string_view from, std::string_view to);

  private:
    boost::asio::awaitable<void> do_listen(boost::asio::ip::tcp::endpoint endpoint);

  private:
    Protocol protocol;
    unsigned short port;
    std::string name;
    detail::Documents documents;
    detail::Redirects redirects;
    static constexpr int threads{4};
    boost::asio::io_context ioc{threads};
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12};
    std::vector<std::thread> workers;
    std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("test:server")};
  };
} // namespace unfold::http

#endif // NET_HTTP_SERVER_HH
