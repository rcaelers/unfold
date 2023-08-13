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

#include "http/HttpClient.hh"

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
#include "HttpStream.hh"

#include <boost/outcome/result.hpp>
#include <utility>

#if defined(WIN32)
#  include <wincrypt.h>
#endif

using namespace unfold::http;

boost::asio::awaitable<outcome::std_result<Response>>
HttpClient::get(std::string url)
{
  HttpStream s(options_);
  auto rc = co_await s.execute(url);

  if (!rc)
    {
      co_return rc.as_failure();
    }
  co_return std::make_pair(rc.value().base().result_int(), rc.value().body().data());
}

boost::asio::awaitable<outcome::std_result<Response>>
HttpClient::get(std::string url, std::string filename, ProgressCallback cb)
{
  HttpStream s(options_);
  auto rc = co_await s.execute(url, filename, cb);

  if (!rc)
    {
      co_return rc.as_failure();
    }

  co_return std::make_pair(rc.value().base().result_int(), "");
}
