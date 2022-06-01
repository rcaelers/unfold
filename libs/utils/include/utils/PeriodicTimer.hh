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

#ifndef UTILS_PERIODIC_TIMER_HH
#define UTILS_PERIODIC_TIMER_HH

#include <chrono>
#include <mutex>
#include <boost/asio.hpp>

namespace unfold::utils
{
  class PeriodicTimer
  {
  public:
    using timer_callback_t = std::function<boost::asio::awaitable<void>()>;

    explicit PeriodicTimer(boost::asio::io_context *ioc);
    ~PeriodicTimer();

    void set_callback(timer_callback_t callback);
    void set_enabled(bool enabled);
    void set_interval(std::chrono::seconds interval);

    PeriodicTimer(const PeriodicTimer &) = delete;
    PeriodicTimer &operator=(const PeriodicTimer &) = delete;
    PeriodicTimer(PeriodicTimer &&) = delete;
    PeriodicTimer &operator=(PeriodicTimer &&) = delete;

  private:
    void update();
    void call_callback();

  private:
    boost::asio::io_context *ioc_;
    std::mutex mutex;
    bool enabled_{false};
    std::chrono::seconds interval_{12};
    timer_callback_t callback_;
    boost::asio::steady_timer timer_;
  };
} // namespace unfold::utils

#endif // UTILS_PERIODIC_TIMER_HH
