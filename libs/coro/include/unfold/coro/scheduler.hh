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

#ifndef UNFOLD_CORO_SCHEDULER_HH
#define UNFOLD_CORO_SCHEDULER_HH

#include <chrono>
#include <exception>
#include <utility>

#include "coro.hh"

namespace unfold::coro
{
  template<typename ValueType>
  class [[nodiscard]] task;

  struct sleep_awaiter : std::suspend_always
  {
    explicit sleep_awaiter(std::chrono::milliseconds duration)
      : duration_(duration)
    {
    }

    void await_suspend(std::coroutine_handle<> h)
    {
      handle_ = h;
    }

  private:
    std::coroutine_handle<> handle_;
    std::chrono::milliseconds duration_{};
  };

  class scheduler
  {
  public:
    virtual ~scheduler() = default;
    virtual auto get_executor() const = 0;
    virtual void spawn(task<void> &&task) = 0;
    virtual sleep_awaiter sleep(int duration) = 0;
  };

} // namespace unfold::coro

#endif // UNFOLD_CORO_SCHEDULER_HH
