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

#ifndef NET_CONNECTION_HH
#define NET_CONNECTION_HH

#include <string>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/url/url.hpp>
#include <boost/outcome/std_result.hpp>

#include "utils/Logging.hh"

#include "http/HttpClient.hh"
#include "http/HttpClientErrors.hh"

namespace outcome = boost::outcome_v2;

class Connection
{
public:
  Connection(boost::asio::any_io_executor, boost::asio::ssl::context &ctx);

  boost::asio::awaitable<outcome::std_result<unfold::http::Response>> get(const std::string &url);
  boost::asio::awaitable<outcome::std_result<unfold::http::Response>> get(const std::string &url,
                                                                          std::ostream &file,
                                                                          unfold::http::ProgressCallback cb);

private:
  boost::asio::awaitable<outcome::std_result<void>> send_request();
  boost::asio::awaitable<outcome::std_result<unfold::http::Response>> receive_reponse();
  boost::asio::awaitable<outcome::std_result<unfold::http::Response>> receive_reponse(std::ostream &file,
                                                                                      unfold::http::ProgressCallback cb);
  boost::asio::awaitable<void> shutdown();
  outcome::std_result<void> parse_url(const std::string &u);

private:
  static constexpr int BUFFER_SIZE = 1024;
  static constexpr std::chrono::seconds TIMEOUT{30};

  boost::urls::url_view url;
  boost::beast::ssl_stream<boost::beast::tcp_stream> stream;
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold::http:connection")};
};

#endif // NET_CONNECTION_HH
