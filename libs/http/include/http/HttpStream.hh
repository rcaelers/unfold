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

#ifndef NET_HTTP_HTTPSTREAM_HH
#define NET_HTTP_HTTPSTREAM_HH

#include <string>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/http.hpp>
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
    using request_t = boost::beast::http::request<boost::beast::http::string_body>;
    using response_t = boost::beast::http::response<boost::beast::http::string_body>;
    using file_response_t = boost::beast::http::response_parser<boost::beast::http::file_body>;
    using secure_stream_t = boost::beast::ssl_stream<boost::beast::tcp_stream>;
    using plain_stream_t = boost::beast::tcp_stream;

    explicit HttpStream(unfold::http::Options options);

    boost::asio::awaitable<outcome::std_result<HttpStream::response_t>> execute(std::string url,
                                                                                std::string filename = "",
                                                                                ProgressCallback cb = ProgressCallback());

  private:
    bool is_redirect(auto code);
    bool is_ok(auto code);
    bool is_tls_connection();
    bool is_tls_requested();

    outcome::std_result<void> init_certificates();

    outcome::std_result<boost::urls::url> parse_url(const std::string &u);
    boost::urls::url get_connect_url();
    bool connect_required();
    boost::asio::awaitable<outcome::std_result<void>> connect();
    boost::asio::awaitable<outcome::std_result<void>> encrypt_connection(boost::urls::url url);
    boost::asio::awaitable<outcome::std_result<void>> proxy_connection();

    template<typename StreamType>
    boost::asio::awaitable<outcome::std_result<void>> proxy_connection(StreamType stream);
    boost::asio::awaitable<outcome::std_result<HttpStream::response_t>> send_receive_request(std::string filename,
                                                                                             ProgressCallback cb);
    boost::beast::http::request<boost::beast::http::string_body> create_request();
    outcome::std_result<bool> handle_redirect(response_t response);

    template<typename StreamType>
    boost::asio::awaitable<outcome::std_result<HttpStream::response_t>> send_receive_request(StreamType stream,
                                                                                             std::string filename,
                                                                                             ProgressCallback cb);
    template<typename StreamType>
    boost::asio::awaitable<outcome::std_result<void>> send_request(StreamType stream, request_t request);
    template<typename StreamType>
    boost::asio::awaitable<outcome::std_result<HttpStream::response_t>> receive_response_body(StreamType stream);
    template<typename StreamType>
    boost::asio::awaitable<outcome::std_result<HttpStream::response_t>> receive_response_body_as_file(StreamType stream,
                                                                                                      std::string filename,
                                                                                                      ProgressCallback cb);
    boost::asio::awaitable<void> shutdown();
    template<typename StreamType>
    boost::asio::awaitable<void> shutdown_impl(StreamType stream);

#if defined(WIN32)
    void add_windows_root_certs(boost::asio::ssl::context &ctx);
#endif

  private:
    static constexpr int BUFFER_SIZE = 1024;

    unfold::http::Options options;
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12_client};
    std::shared_ptr<plain_stream_t> plain_stream;
    std::shared_ptr<secure_stream_t> secure_stream;
    int redirect_count{0};
    boost::urls::url requested_url;
    std::optional<boost::urls::url> connected_url;
    std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold::http:connection")};
  };
} // namespace unfold::http

#endif // NET_HTTP_HTTPSTREAM_HH
