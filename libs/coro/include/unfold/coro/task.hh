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

#ifndef UNFOLD_CORO_TASK_HH
#define UNFOLD_CORO_TASK_HH

#include <exception>
#include <utility>
#include <variant>
#include <coroutine>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include "promise.hh"

namespace unfold::coro
{
  namespace detail
  {
    template<typename Promise>
    class task_awaitable
    {
    public:
      explicit task_awaitable(std::coroutine_handle<Promise> coroutine) noexcept
        : handle_(coroutine)
      {
      }

      auto await_ready() const noexcept -> bool
      {
        return !handle_ || handle_.done();
      }

      template<typename P>
      auto await_suspend(std::coroutine_handle<P> awaiting_coroutine) const noexcept -> std::coroutine_handle<>
      {
        handle_.promise().set_continuation(awaiting_coroutine);
        handle_.promise().set_scheduler(awaiting_coroutine.promise().scheduler());
        handle_.promise().set_io_context(awaiting_coroutine.promise().io_context());
        return handle_;
      }

      auto await_resume()
      {
        if constexpr (std::is_void_v<decltype(this->handle_.promise().result())>)
          {
            return this->handle_.promise().result();
          }
        else
          {
            return std::move(this->handle_.promise().result());
          }
      }

    private:
      std::coroutine_handle<Promise> handle_{nullptr};
    };
  } // namespace detail

  template<typename ValueType, typename SchedulerType>
  class [[nodiscard]] task
  {
  public:
    using promise_type = detail::promise<ValueType, SchedulerType>;

    task() noexcept = default;

    explicit task(std::coroutine_handle<promise_type> handle) noexcept
      : handle_(handle)
    {
    }

    ~task()
    {
      if (handle_ != nullptr)
        {
          handle_.destroy();
        }
    }

    task(const task &) noexcept = delete;
    auto operator=(const task &) noexcept -> task & = delete;

    task(task &&other) noexcept
      : handle_(std::exchange(other.handle_, nullptr))
    {
    }

    auto operator=(task &&other) noexcept -> task &
    {
      if (std::addressof(other) != this)
        {
          if (handle_ != nullptr)
            {
              handle_.destroy();
            }

          handle_ = std::exchange(other.handle_, nullptr);
        }

      return *this;
    }

    auto resume() -> bool
    {
      if (!handle_.done())
        {
          handle_.resume();
        }
      return !handle_.done();
    }

    auto handle() -> std::coroutine_handle<promise_type>
    {
      return handle_;
    }

    auto set_scheduler(SchedulerType *scheduler)
    {
      return handle_.promise().set_scheduler(scheduler);
    }

    auto set_io_context(boost::asio::io_context *ioc)
    {
      return handle_.promise().set_io_context(ioc);
    }

    auto scheduler() -> SchedulerType *
    {
      return handle_.promise().scheduler();
    }

    auto operator co_await() & = delete;

    auto operator co_await() const && noexcept
    {
      return detail::task_awaitable{handle_};
    }

  private:
    std::coroutine_handle<promise_type> handle_{nullptr};
  };
} // namespace unfold::coro

#endif // UNFOLD_CORO_TASK_HH
