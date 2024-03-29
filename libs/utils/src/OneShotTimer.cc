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
#include <chrono>
#include <utility>

#include "utils/OneShotTimer.hh"

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

using namespace unfold::utils;

OneShotTimer::OneShotTimer(boost::asio::io_context *ioc)
  : ioc_(ioc)
  , timer_(*ioc)
{
}

OneShotTimer::~OneShotTimer()
{
  timer_.cancel();
}

void
OneShotTimer::set_callback(timer_callback_t callback)
{
  callback_ = std::move(callback);
}

void
OneShotTimer::schedule(std::chrono::seconds delay)
{
  timer_.expires_at(std::chrono::system_clock::now() + delay);
  timer_.async_wait([this](const boost::system::error_code &ec) {
    if (!ec)
      {
        call_callback();
      }
  });
}

void
OneShotTimer::cancel()
{
  timer_.cancel();
}

void
OneShotTimer::call_callback()
{
  boost::asio::co_spawn(
    *ioc_,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          co_await callback_();
        }
      catch (std::exception &e)
        {
        }
    },
    boost::asio::detached);
}
