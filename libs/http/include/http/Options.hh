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

#ifndef NET_HTTP_OPTIONS_HH
#define NET_HTTP_OPTIONS_HH

#include <list>
#include <string>

#include <boost/outcome/std_result.hpp>

#include "utils/Logging.hh"

namespace unfold::http
{
  namespace outcome = boost::outcome_v2;

  class Options
  {
  public:
    Options() = default;

    enum class ProxyType
    {
      None,
      System,
      Custom
    };

    void add_ca_cert(const std::string &cert);
    void set_keep_alive(bool keep_alive);
    void set_follow_redirects(bool follow_redirects);
    void set_max_redirects(int max_redirects);
    void set_timeout(std::chrono::seconds timeout);
    void set_proxy(ProxyType proxy);
    void set_custom_proxy(const std::string &proxy);
    void set_progress_callback(std::function<void(double progress)> progress_callback);

    std::list<std::string> get_ca_certs() const;
    bool get_keep_alive() const;
    bool get_follow_redirects() const;
    int get_max_redirects() const;
    std::chrono::seconds get_timeout() const;
    std::string get_custom_proxy() const;
    ProxyType get_proxy() const;
    std::function<void(double progress)> get_progress_callback() const;

  private:
    std::list<std::string> ca_certs;
    bool keep_alive = true;
    bool follow_redirects = true;
    int max_redirects = 5;
    ProxyType proxy = ProxyType::None;
    std::string custom_proxy;
    std::chrono::seconds timeout = std::chrono::seconds(30);
    std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:http")};
  };

  inline std::ostream &operator<<(std::ostream &os, Options::ProxyType type)
  {
    switch (type)
      {
      case Options::ProxyType::None:
        os << "None";
        break;
      case Options::ProxyType::System:
        os << "System";
        break;
      case Options::ProxyType::Custom:
        os << "Custom";
        break;
      }
    return os;
  }

} // namespace unfold::http

#endif // NET_HTTP_OPTIONS_HH
