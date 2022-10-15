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

#include <cassert>
#include <utility>

#include "utils/PeriodicTimer.hh"

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

using namespace unfold::utils;

PeriodicTimer::PeriodicTimer(boost::asio::io_context *ioc)
  : ioc_(ioc)
  , timer_(*ioc, interval_)
{
}

PeriodicTimer::~PeriodicTimer()
{
  timer_.cancel();
}

void
PeriodicTimer::set_callback(timer_callback_t callback)
{
  std::scoped_lock lock(mutex);
  callback_ = std::move(callback);
}

void
PeriodicTimer::set_enabled(bool enabled)
{
  std::scoped_lock lock(mutex);
  assert(callback_);
  enabled_ = enabled;
  update();
}

void
PeriodicTimer::set_interval(std::chrono::seconds interval)
{
  std::scoped_lock lock(mutex);
  interval_ = interval;
  update();
}

void
PeriodicTimer::update()
{
  if (enabled_)
    {
      timer_.expires_from_now(interval_);
      timer_.async_wait([this](const boost::system::error_code &ec) {
        if (!ec)
          {
            call_callback();
          }
      });
    }
  else
    {
      timer_.cancel();
    }
}

void
PeriodicTimer::call_callback()
{
  boost::asio::co_spawn(
    *ioc_,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          co_await callback_();
          std::scoped_lock lock(mutex);
          update();
        }
      catch (std::exception &e)
        {
        }
    },
    boost::asio::detached);
}
