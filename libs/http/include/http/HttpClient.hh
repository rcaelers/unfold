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

#ifndef NET_HTTP_CLIENT_HH
#define NET_HTTP_CLIENT_HH

#include <string>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/outcome/std_result.hpp>

#include "utils/Logging.hh"

namespace unfold::http
{
  using ProgressCallback = std::function<void(double progress)>;
  using Response = std::pair<int, std::string>;

  namespace outcome = boost::outcome_v2;

  class HttpClient
  {
  public:
    HttpClient();

    outcome::std_result<void> add_ca_cert(const std::string &cert);

    boost::asio::awaitable<outcome::std_result<Response>> get(const std::string &url, std::ostream &file, ProgressCallback cb);
    boost::asio::awaitable<outcome::std_result<Response>> get(const std::string &url);

  private:
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12_client};
    std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:http")};
  };
} // namespace unfold::http

#endif // NET_HTTP_CLIENT_HH
