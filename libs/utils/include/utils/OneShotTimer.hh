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

#ifndef UTILS_ONESHOT_TIMER_HH
#define UTILS_ONESHOT_TIMER_HH

#include <chrono>
#include <mutex>
#include <boost/asio.hpp>

namespace unfold::utils
{
  class OneShotTimer
  {
  public:
    using timer_callback_t = std::function<boost::asio::awaitable<void>()>;

    explicit OneShotTimer(boost::asio::io_context *ioc);
    ~OneShotTimer();

    void set_callback(timer_callback_t callback);

    template<typename Rep, typename Period>
    void schedule(std::chrono::duration<Rep, Period> delay)
    {
      schedule(std::chrono::duration_cast<std::chrono::seconds>(delay));
    }

    void schedule(std::chrono::seconds delay);

    void cancel();

    OneShotTimer(const OneShotTimer &) = delete;
    OneShotTimer &operator=(const OneShotTimer &) = delete;
    OneShotTimer(OneShotTimer &&) = delete;
    OneShotTimer &operator=(OneShotTimer &&) = delete;

  private:
    void call_callback();

  private:
    boost::asio::io_context *ioc_;
    timer_callback_t callback_;
    boost::asio::steady_timer timer_;
  };
} // namespace unfold::utils

#endif // UTILS_ONESHOT_TIMER_HH
