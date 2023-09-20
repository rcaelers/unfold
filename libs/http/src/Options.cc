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

#include "http/Options.hh"

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include "boost/outcome/outcome.hpp"

using namespace unfold::http;

void
Options::add_ca_cert(const std::string &cert)
{
  ca_certs.push_back(cert);
}

std::list<std::string>
Options::get_ca_certs() const
{
  return ca_certs;
}

void
Options::set_timeout(std::chrono::seconds timeout)
{
  this->timeout = timeout;
}

std::chrono::seconds
Options::get_timeout() const
{
  return timeout;
}

void
Options::set_follow_redirects(bool follow_redirects)
{
  this->follow_redirects = follow_redirects;
}

bool
Options::get_follow_redirects() const
{
  return follow_redirects;
}

void
Options::set_max_redirects(int max_redirects)
{
  this->max_redirects = max_redirects;
}

int
Options::get_max_redirects() const
{
  return max_redirects;
}

void
Options::set_custom_proxy(const std::string &custom_proxy)
{
  this->custom_proxy = custom_proxy;
}

void
Options::set_proxy(ProxyType proxy)
{
  this->proxy = proxy;
}

Options::ProxyType
Options::get_proxy() const
{
  return proxy;
}

std::string
Options::get_custom_proxy() const
{
  return custom_proxy;
}
