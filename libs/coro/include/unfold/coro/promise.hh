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

#ifndef UNFOLD_CORO_PROMISE_HH
#define UNFOLD_CORO_PROMISE_HH

#include <exception>
#include <utility>
#include <coroutine>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include "asio.hh"

namespace unfold::coro
{
  template<typename ValueType, typename SchedulerType>
  class [[nodiscard]] task;

  namespace detail
  {
    template<typename ValueType>
    class promise_base
    {
    public:
      promise_base() noexcept = default;
      ~promise_base() = default;

      auto unhandled_exception() -> void
      {
        result_ = std::current_exception();
      }

      auto return_value(ValueType value) -> void
      {
        result_ = std::move(value);
      }

      auto result() -> ValueType
      {
        if (auto exception = std::get_if<std::exception_ptr>(&result_))
          {
            std::rethrow_exception(*exception);
          }

        return std::get<ValueType>(std::move(result_));
      }

    private:
      std::variant<std::monostate, ValueType, std::exception_ptr> result_;
    };

    template<>
    class promise_base<void>
    {
    public:
      promise_base() noexcept = default;
      ~promise_base() = default;

      auto unhandled_exception() -> void
      {
        exception_ = std::current_exception();
      }

      auto return_void() noexcept -> void
      {
      }

      auto result() -> void
      {
        if (exception_)
          {
            std::rethrow_exception(exception_);
          }
      }

    private:
      std::exception_ptr exception_;
    };

    template<typename ValueType, typename SchedulerType>
    class promise : public detail::promise_base<ValueType>
    {
      struct final_awaiter
      {
        auto await_ready() const noexcept -> bool
        {
          return false;
        }

        template<typename P>
        auto await_suspend(std::coroutine_handle<P> coroutine) noexcept -> std::coroutine_handle<>
        {
          auto continuation = coroutine.promise().continuation_;
          if (continuation != nullptr)
            {
              return continuation;
            }

          return std::noop_coroutine();
        }

        auto await_resume() noexcept -> void
        {
        }
      };

    public:
      promise() noexcept = default;
      ~promise() = default;

      promise(const promise &) = delete;
      promise &operator=(const promise &) = delete;
      promise(promise &&) = delete;
      promise &operator=(promise &&) = delete;

      auto get_return_object() noexcept -> task<ValueType, SchedulerType>
      {
        return task<ValueType, SchedulerType>{std::coroutine_handle<promise<ValueType, SchedulerType>>::from_promise(*this)};
      }

      auto initial_suspend()
      {
        return std::suspend_always{};
      }

      auto final_suspend() noexcept
      {
        return final_awaiter{};
      }

      template<typename P>
      auto set_continuation(std::coroutine_handle<P> continuation) noexcept -> void
      {
        continuation_ = continuation;
      }

      template<typename U>
      U &&await_transform(U &&awaitable) noexcept
      {
        return static_cast<U &&>(awaitable);
      }

      template<typename R>
      auto await_transform(boost::asio::awaitable<R> awaitable) noexcept
      {
        return detail::asio_awaiter{std::move(awaitable), ioc_, scheduler_};
      }

      auto set_scheduler(SchedulerType *scheduler)
      {
        scheduler_ = scheduler;
      }

      auto scheduler() -> SchedulerType *
      {
        return scheduler_;
      }

      auto set_io_context(boost::asio::io_context *ioc)
      {
        ioc_ = ioc;
      }

      auto io_context()
      {
        return ioc_;
      }

    private:
      std::coroutine_handle<> continuation_{nullptr};
      SchedulerType *scheduler_{nullptr};
      boost::asio::io_context *ioc_{nullptr};
    };
  } // namespace detail
} // namespace unfold::coro

#endif // UNFOLD_CORO_PROMISE_HH
