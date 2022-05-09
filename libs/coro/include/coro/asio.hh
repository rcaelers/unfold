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

#ifndef CORO_ASIO_HH
#define CORO_ASIO_HH

#include <exception>
#include <utility>
#include <optional>

#include <boost/outcome/std_result.hpp>
namespace outcome = boost::outcome_v2;

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include <boost/asio.hpp>

#include "coro.hh"

namespace unfold::coro::detail
{
  class asio_context
  {
  public:
    explicit asio_context(int num_threads)
      : ioc_(num_threads)
      , guard_(boost::asio::make_work_guard(ioc_))
    {
      workers_.reserve(num_threads);
      for (auto i = 0; i < num_threads; i++)
        {
          workers_.emplace_back([this] { ioc_.run(); });
        }
    }

    ~asio_context()
    {
      if (!workers_.empty())
        {
          ioc_.stop();
          for (auto &w: workers_)
            {
              w.join();
            }
          workers_.clear();
        }
    }

    auto &get_io_context()
    {
      return ioc_;
    }

    asio_context(const asio_context &) = delete;
    asio_context &operator=(const asio_context &) = delete;
    asio_context(asio_context &&) = delete;
    asio_context &operator=(asio_context &&) = delete;

  private:
    boost::asio::io_context ioc_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard_;
    std::vector<std::thread> workers_;
  };

  template<typename ValueType, typename SchedulerType>
  class asio_awaiter
  {
  public:
    asio_awaiter(boost::asio::awaitable<outcome::std_result<ValueType>> awaitable, asio_context &context, SchedulerType *scheduler)
      : awaitable_(std::move(awaitable))
      , executer_{scheduler->get_context()}
      , ioc_(context.get_io_context())
    {
    }

    ~asio_awaiter() = default;

    asio_awaiter(const asio_awaiter &) = delete;
    asio_awaiter &operator=(const asio_awaiter &) = delete;
    asio_awaiter(asio_awaiter &&) = delete;
    asio_awaiter &operator=(asio_awaiter &&) = delete;

    auto await_ready() noexcept -> bool
    {
      return false;
    }

    void await_suspend(std::coroutine_handle<> awaiting_coroutine)
    {
      awaiting_coroutine_ = awaiting_coroutine;
      boost::asio::co_spawn(
        ioc_,
        [&]() -> boost::asio::awaitable<std::optional<outcome::std_result<ValueType>>> { co_return co_await std::move(awaitable_); },
        [this](std::exception_ptr e, auto r) {
          exception_ = e;
          result_ = r;
          executer_.execute(awaiting_coroutine_);
        });
    }

    auto await_resume() -> outcome::std_result<ValueType>
    {
      if (exception_)
        {
          std::rethrow_exception(exception_);
        }
      if (result_)
        {
          return *result_;
        }
      throw std::runtime_error("unknown result");
    }

  private:
    boost::asio::awaitable<outcome::std_result<ValueType>> awaitable_;
    typename SchedulerType::executer executer_;
    boost::asio::io_context &ioc_;
    std::coroutine_handle<> awaiting_coroutine_;
    std::optional<outcome::std_result<ValueType>> result_;
    std::exception_ptr exception_;
  };

} // namespace unfold::coro::detail

#endif // CORO_ASIO_HH
