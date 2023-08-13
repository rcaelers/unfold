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

#include "WindowsSystemProxy.hh"

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include <boost/algorithm/string.hpp>
#include "boost/outcome/outcome.hpp"

#include <iostream>

#include "utils/StringUtils.hh"

class IEProxyConfig
{
public:
  IEProxyConfig()
  {
    auto rc = WinHttpGetIEProxyConfigForCurrentUser(&config);
    if (rc == TRUE)
      {
        logger->debug("get_user_config: auto detect: {}", config.fAutoDetect);
        if (config.lpszAutoConfigUrl != nullptr)
          {
            logger->debug("get_user_config: auto config url: {}", unfold::utils::utf16_to_utf8(config.lpszAutoConfigUrl));
          }
        if (config.lpszProxy != nullptr)
          {
            logger->debug("get_user_config: proxy: {}", unfold::utils::utf16_to_utf8(config.lpszProxy));
          }
        if (config.lpszProxyBypass != nullptr)
          {
            logger->debug("get_user_config: proxy bypass: {}", unfold::utils::utf16_to_utf8(config.lpszProxyBypass));
          }
      }
    else if (GetLastError() == ERROR_FILE_NOT_FOUND)
      {
        config = {};
        config.fAutoDetect = TRUE;
      }
  }

  ~IEProxyConfig()
  {
    if (config.lpszAutoConfigUrl != nullptr)
      {
        GlobalFree(config.lpszAutoConfigUrl);
      }

    if (config.lpszProxy != nullptr)
      {
        GlobalFree(config.lpszProxy);
      }

    if (config.lpszProxyBypass != nullptr)
      {
        GlobalFree(config.lpszProxyBypass);
      }
  }

  IEProxyConfig(const IEProxyConfig &) = delete;
  IEProxyConfig &operator=(const IEProxyConfig &) = delete;
  IEProxyConfig(IEProxyConfig &&) = delete;
  IEProxyConfig &operator=(IEProxyConfig &&) = delete;

  WINHTTP_CURRENT_USER_IE_PROXY_CONFIG config = {};

private:
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold::http:windows:system_proxy")};
};

class WinHttpProxyInfo
{

public:
  WinHttpProxyInfo() = default;
  ~WinHttpProxyInfo()
  {
    if (info.lpszProxy != nullptr)
      {
        GlobalFree(info.lpszProxy);
      }

    if (info.lpszProxyBypass != nullptr)
      {
        GlobalFree(info.lpszProxyBypass);
      }
  }
  WinHttpProxyInfo(const WinHttpProxyInfo &) = delete;
  WinHttpProxyInfo &operator=(const WinHttpProxyInfo &) = delete;

  WinHttpProxyInfo(WinHttpProxyInfo &&other) noexcept
    : info(other.info)
  {
    other.info = {};
  }

  WinHttpProxyInfo &operator=(WinHttpProxyInfo &&other) noexcept
  {
    if (this != &other)
      {
        info = other.info;
        other.info = {};
      }
    return *this;
  }

  WINHTTP_PROXY_INFO info = {};
};

class WinHttpSession
{
public:
  WinHttpSession()
    : session(WinHttpOpen(L"Unfold", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0))
  {
  }

  ~WinHttpSession()
  {
    WinHttpCloseHandle(session);
  }

  auto get_proxy_for_url(std::string url, WINHTTP_AUTOPROXY_OPTIONS &auto_proxy_options) const
  {
    WinHttpProxyInfo auto_proxy_info{};
    auto rc = WinHttpGetProxyForUrl(session,
                                    unfold::utils::utf8_to_utf16(url).c_str(),
                                    &auto_proxy_options,
                                    &auto_proxy_info.info);
    return std::make_tuple(rc, std::move(auto_proxy_info));
  }

  bool is_ok() const
  {
    return session != nullptr;
  }

  WinHttpSession(const WinHttpSession &) = delete;
  WinHttpSession &operator=(const WinHttpSession &) = delete;
  WinHttpSession(WinHttpSession &&) = delete;
  WinHttpSession &operator=(WinHttpSession &&) = delete;

  HINTERNET session = {};
};

std::optional<std::string>
WindowsSystemProxy::handle_proxy_list(std::string proxy_list)
{
  std::vector<std::string> proxies;
  boost::algorithm::split(proxies, proxy_list, boost::is_any_of(";"));
  if (!proxies.empty())
    {
      auto result = proxies[0];
      if (!result.starts_with("http://"))
        {
          result = "http://" + result;
        }
      return result;
    }
  return {};
}

boost::asio::awaitable<std::optional<std::string>>
WindowsSystemProxy::get_system_proxy_for_url(std::string url)
{
  co_return co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(std::optional<std::string>)>(
    [this, url](auto &&self) {
      std::thread([this, url, self = std::move(self)]() mutable {
        auto result = get_system_proxy_for_url_sync(url);
        self.complete(result);
      }).detach();
    },
    boost::asio::use_awaitable);
}

std::optional<std::string>
WindowsSystemProxy::get_system_proxy_for_url_sync(std::string url)
{
  IEProxyConfig ie_proxy_config;
  auto &config = ie_proxy_config.config;

  if (ie_proxy_config.config.lpszProxy != nullptr)
    {
      logger->debug("get_system_proxy_for_url: IE proxy: {}", unfold::utils::utf16_to_utf8(config.lpszProxy));
      return handle_proxy_list(unfold::utils::utf16_to_utf8(config.lpszProxy));
    }

  if ((config.lpszAutoConfigUrl != nullptr) || config.fAutoDetect == TRUE)
    {
      WINHTTP_AUTOPROXY_OPTIONS auto_proxy_options{};

      if (config.lpszAutoConfigUrl != nullptr)
        {
          auto_proxy_options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
          auto_proxy_options.lpszAutoConfigUrl = config.lpszAutoConfigUrl;
        }
      else
        {
          auto_proxy_options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
          auto_proxy_options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        }

      WinHttpSession session;

      if (!session.is_ok())
        {
          logger->error("Failed to open http session: {}", GetLastError());
          return {};
        }

      auto_proxy_options.fAutoLogonIfChallenged = FALSE;

      auto [rc, auto_proxy_info] = session.get_proxy_for_url(url, auto_proxy_options);

      if ((rc == FALSE) && GetLastError() == ERROR_WINHTTP_LOGIN_FAILURE)
        {
          auto_proxy_options.fAutoLogonIfChallenged = TRUE;
          std::tie(rc, auto_proxy_info) = session.get_proxy_for_url(url, auto_proxy_options);
        }

      if (rc == FALSE)
        {
          logger->error("Failed to get proxy for url: {}", GetLastError());
          return {};
        }

      if (auto_proxy_info.info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY)
        {
          return handle_proxy_list(unfold::utils::utf16_to_utf8(auto_proxy_info.info.lpszProxy));
        }
    }

  return {};
}
