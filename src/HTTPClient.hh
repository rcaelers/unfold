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

#ifndef HTTPClient_HH
#define HTTPClient_HH

#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>

#include "Logging.hh"

using ProgressCallback = std::function<void(double progress)>;

using Response = std::pair<int, std::string>;

class Request
{
public:
  Request(std::string url, boost::asio::io_context &ioc, boost::asio::ssl::context &ctx);

  boost::asio::awaitable<Response> get();
  boost::asio::awaitable<Response> download(const std::string &filename, ProgressCallback cb);

private:
  boost::asio::awaitable<Response> receive_reponse();
  boost::asio::awaitable<Response> download_reponse(const std::string &filename, ProgressCallback cb);
  boost::asio::awaitable<void> request();
  boost::asio::awaitable<void> shutdown();

private:
  static constexpr int BUFFER_SIZE = 1024;
  static constexpr std::chrono::seconds TIMEOUT{30};

  std::string url;
  boost::asio::io_context &ioc;
  boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  std::shared_ptr<spdlog::logger> logger{Logging::create("unfold::http:request")};
};

class HTTPClient
{
public:
  HTTPClient();

  void add_ca_cert(const std::string &cert);

  Response download(const std::string &url, const std::string &filename, ProgressCallback cb);
  Response get(const std::string &url);

private:
  boost::asio::io_context ioc;
  boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12_client};
  std::shared_ptr<spdlog::logger> logger{Logging::create("unfold:http")};
};
#endif
