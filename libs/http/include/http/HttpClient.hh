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

#ifndef NET_HTTP_HTTPCLIENT_HH
#define NET_HTTP_HTTPCLIENT_HH

#include <string>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/url/url.hpp>
#include <boost/url/url_view.hpp>
#include <boost/outcome/std_result.hpp>

#include "utils/Logging.hh"

#include "http/Options.hh"
#include "http/HttpClientErrors.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::http
{
  using Response = std::pair<int, std::string>;
  using ProgressCallback = std::function<void(double progress)>;

  class HttpClient
  {
  public:
    HttpClient() = default;

    Options &options()
    {
      return options_;
    }

    boost::asio::awaitable<outcome::std_result<unfold::http::Response>> get(std::string url);
    boost::asio::awaitable<outcome::std_result<unfold::http::Response>> get(std::string url,
                                                                            std::string file,
                                                                            unfold::http::ProgressCallback cb);

  private:
    unfold::http::Options options_;
  };
} // namespace unfold::http
#endif // NET_HTTP_HTTPCLIENT_HH
