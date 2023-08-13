// Copyright (C) 2023 Rob Caelers <rob.caelers@gmail.com>
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

#ifndef WINDOWS_SYSTEM_PROXY
#define WINDOWS_SYSTEM_PROXY

#include <boost/asio.hpp>
#include <boost/asio/experimental/as_tuple.hpp>
#include <boost/asio/spawn.hpp>

#include <windows.h>
#include <winhttp.h>

#include <boost/outcome/std_result.hpp>
#include "utils/Logging.hh"

#include "SystemProxy.hh"

namespace outcome = boost::outcome_v2;

class WindowsSystemProxy : public SystemProxy
{
public:
  WindowsSystemProxy() = default;
  boost::asio::awaitable<std::optional<std::string>> get_system_proxy_for_url(std::string url) override;
  std::optional<std::string> get_system_proxy_for_url_sync(std::string url);

private:
  std::optional<std::string> handle_proxy_list(std::string proxy_list);
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold::http:windows:system_proxy")};
};

#endif // WINDOWS_SYSTEM_PROXY
