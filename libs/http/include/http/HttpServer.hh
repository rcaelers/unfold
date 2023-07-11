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

#ifndef HTTP_SERVER_HH
#define HTTP_SERVER_HH

#include <thread>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/config.hpp>
#include <string_view>

#include <spdlog/spdlog.h>

#include "utils/Logging.hh"

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
      Session(StreamType &&stream, Documents documents, detail::Redirects redirects)
        : stream(std::move(stream))
        , documents(std::move(documents))
        , redirects(std::move(redirects))
      {
      }

    private:
      template<bool isRequest, class Body, class Fields>
      bool send(boost::beast::http::message<isRequest, Body, Fields> &&msg,
                boost::beast::error_code &ec,
                boost::asio::yield_context yield)
      {
        auto eof = msg.need_eof();
        boost::beast::http::serializer<isRequest, Body, Fields> sr{msg};
        boost::beast::http::async_write(stream, sr, yield[ec]);
        return eof;
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

      void send_error(boost::beast::http::status status,
                      const std::string &text,
                      boost::beast::error_code &ec,
                      boost::asio::yield_context yield)
      {
        logger->error("sending http response: ({})", text);

        boost::beast::http::response<boost::beast::http::string_body> res{status, req.version()};
        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(boost::beast::http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = text;
        res.prepare_payload();
        send(std::move(res), ec, yield);
      }

      void send_bad_request(std::string_view why, boost::beast::error_code &ec, boost::asio::yield_context yield)
      {
        send_error(boost::beast::http::status::bad_request, std::string(why), ec, yield);
      }

      void send_not_found(std::string_view target, boost::beast::error_code &ec, boost::asio::yield_context yield)
      {
        send_error(boost::beast::http::status::not_found, "The resource '" + std::string(target) + "' was not found.", ec, yield);
      }

      void send_redirect(const std::string_view location, boost::beast::error_code &ec, boost::asio::yield_context yield)
      {
        logger->error("sending http redirect response: ({})", location);

        boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::found, req.version()};
        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(boost::beast::http::field::location, location);
        res.keep_alive(req.keep_alive());
        res.prepare_payload();
        send(std::move(res), ec, yield);
      }

    protected:
      bool handle_request(boost::beast::error_code &ec, boost::asio::yield_context yield)
      {
        if (req.method() != boost::beast::http::verb::get)
          {
            send_bad_request("Unknown HTTP method", ec, yield);
            return false;
          }

        if (redirects.exists(req.target()))
          {
            auto location = redirects.get(req.target());
            send_redirect(location, ec, yield);
            return false;
          }

        if (documents.exists(req.target()))
          {
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
            return send(std::move(res), ec, yield);
          }

        send_not_found(req.target(), ec, yield);
        return false;
      }

    protected:
      StreamType stream;
      boost::beast::http::request<boost::beast::http::string_body> req;

    private:
      Documents documents;
      Redirects redirects;
      std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("test:server:session")};
    };

    class PlainSession : public Session<boost::beast::tcp_stream>
    {
    public:
      PlainSession(boost::asio::ip::tcp::socket socket, Documents documents, detail::Redirects redirects)
        : Session<boost::beast::tcp_stream>(boost::beast::tcp_stream(std::move(socket)), documents, redirects)
      {
      }

      void run(boost::asio::yield_context yield);

    private:
      std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("test:server:plainsession")};
    };

    class SecureSession : public Session<boost::beast::ssl_stream<boost::beast::tcp_stream>>
    {
    public:
      SecureSession(boost::asio::ip::tcp::socket socket,
                    boost::asio::ssl::context &ctx,
                    Documents documents,
                    detail::Redirects redirects)
        : Session<boost::beast::ssl_stream<boost::beast::tcp_stream>>({std::move(socket), ctx}, documents, redirects)
      {
      }

      void run(boost::asio::yield_context yield);

    private:
      std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("test:server:securesession")};
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
    void run();
    void stop();

    void add(std::string_view file, const std::string &body);
    void add_file(std::string_view file, const std::string &filename);
    void add_redirect(std::string_view from, std::string_view to);

  private:
    void do_listen(boost::asio::ip::tcp::endpoint endpoint, boost::asio::yield_context yield);

  private:
    Protocol protocol;
    unsigned short port;
    detail::Documents documents;
    detail::Redirects redirects;
    static constexpr int threads{4};
    boost::asio::io_context ioc{threads};
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12};
    std::vector<std::thread> workers;
    std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("test:server")};
  };
} // namespace unfold::http

#endif // HTTP_SERVER_HH
