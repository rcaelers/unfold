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

#include <spdlog/spdlog.h>

#include "Logging.hh"

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

class Connection
{
public:
  Connection(boost::beast::ssl_stream<boost::beast::tcp_stream> &stream, Documents &documents);

  void run(boost::asio::yield_context yield);

private:
  template<bool isRequest, class Body, class Fields>
  bool send(boost::beast::http::message<isRequest, Body, Fields> &&msg,
            boost::beast::error_code &ec,
            boost::asio::yield_context yield) const
  {
    auto eof = msg.need_eof();
    boost::beast::http::serializer<isRequest, Body, Fields> sr{msg};
    boost::beast::http::async_write(stream, sr, yield[ec]);
    return eof;
  }

  boost::beast::string_view mime_type(boost::beast::string_view path);

  void send_error(boost::beast::http::status status,
                  const std::string &text,
                  boost::beast::error_code &ec,
                  boost::asio::yield_context yield) const;
  void send_bad_request(boost::beast::string_view why, boost::beast::error_code &ec, boost::asio::yield_context yield) const;
  void send_not_found(boost::beast::string_view target, boost::beast::error_code &ec, boost::asio::yield_context yield) const;
  bool handle_request(boost::beast::error_code &ec, boost::asio::yield_context yield);

private:
  boost::beast::ssl_stream<boost::beast::tcp_stream> &stream;
  Documents &documents;
  boost::beast::http::request<boost::beast::http::string_body> req;
  std::shared_ptr<spdlog::logger> logger{Logging::create("test:server:connection")};
};

class HTTPServer
{
public:
  void run();
  void stop();

  void add(std::string_view file, const std::string &body);

private:
  void do_listen(boost::asio::ip::tcp::endpoint endpoint, boost::asio::yield_context yield);

private:
  Documents documents;
  static constexpr int threads{4};
  boost::asio::io_context ioc{threads};
  boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12};
  std::vector<std::thread> workers;
  std::shared_ptr<spdlog::logger> logger{Logging::create("test:server")};
};

#endif // HTTP_SERVER_HH
