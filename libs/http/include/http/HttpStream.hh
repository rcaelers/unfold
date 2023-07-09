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

#ifndef NET_HTTP_HTTPSTREAM_HH
#define NET_HTTP_HTTPSTREAM_HH

#include <string>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/url/url.hpp>
#include <boost/url/url_view.hpp>
#include <boost/outcome/std_result.hpp>

#include "utils/Logging.hh"

#include "http/Options.hh"
#include "http/HttpClient.hh"
#include "http/HttpClientErrors.hh"

namespace outcome = boost::outcome_v2;

namespace unfold::http
{
  class HttpStream
  {
  public:
    explicit HttpStream(unfold::http::Options options = unfold::http::Options());

    boost::asio::awaitable<outcome::std_result<unfold::http::Response>> get(std::string url);
    boost::asio::awaitable<outcome::std_result<unfold::http::Response>> get(std::string url,
                                                                            std::ostream &file,
                                                                            unfold::http::ProgressCallback cb);

  private:
    bool is_redirect(auto code);
    bool is_ok(auto code);

    outcome::std_result<void> init_certificates();

    boost::asio::awaitable<outcome::std_result<void>> send_request();
    boost::asio::awaitable<outcome::std_result<unfold::http::Response>> receive_response(std::ostream &out,
                                                                                         unfold::http::ProgressCallback cb);
    boost::asio::awaitable<void> shutdown();
    outcome::std_result<void> parse_url(const std::string &u);

#if defined(WIN32)
    void add_windows_root_certs(boost::asio::ssl::context &ctx);
#endif

  private:
    static constexpr int BUFFER_SIZE = 1024;
    static constexpr std::chrono::seconds TIMEOUT{30};

    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12_client};
    std::shared_ptr<boost::beast::ssl_stream<boost::beast::tcp_stream>> stream;
    unfold::http::Options options;
    std::list<std::string> ca_certs;
    boost::urls::url_view url;
    std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold::http:connection")};
  };
} // namespace unfold::http

#endif // NET_HTTP_HTTPSTREAM_HH
