// Copyright (C) 2025 Rob Caelers <rob.caelers@gmail.com>
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

#ifndef UNFOLD_CORO_QTTASK_HH
#define UNFOLD_CORO_QTTASK_HH

#include <memory>
#include <utility>
#include <coroutine>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include <QtGui>
#include <QTimer>

#include "unfold/coro/task.hh"

namespace unfold::coro
{
  namespace qt
  {

    namespace detail
    {
      template<class F>
      class function
      {
      public:
        function() = default;
        function(F &&f)
          : func_(std::make_shared<F>(std::move(f)))
        {
        }
        ~function() = default;
        function(const function &) = default;
        function &operator=(const function &) = default;
        function(function &&) noexcept = default;
        function &operator=(function &&) noexcept = default;

        template<class... Arg>
        auto operator()(Arg &&...arg) const
        {
          return (*func_)(std::forward<Arg>(arg)...);
        }

      private:
        std::shared_ptr<F> func_;
      };

      template<class F>
      function<std::decay_t<F>> make_function(F &&f)
      {
        return {std::forward<F>(f)};
      }
    } // namespace detail

    class executer
    {
    public:
      explicit executer(QObject *thread)
        : thread_(thread)
      {
      }
      ~executer() = default;

      executer(const executer &) = delete;
      executer &operator=(const executer &) = delete;

      executer(executer &&other) noexcept
        : func_(std::exchange(other.func_, nullptr))
        , thread_(std::exchange(other.thread_, nullptr))
      {
      }

      auto operator=(executer &&other) noexcept -> executer &
      {
        if (std::addressof(other) != this)
          {
            func_ = std::exchange(other.func_, nullptr);
            thread_ = std::exchange(other.thread_, nullptr);
          }

        return *this;
      }

      void execute(auto f)
      {
        func_ = detail::make_function(std::move(f));
        QMetaObject::invokeMethod(thread_, [this]() { this->func_(); });
      }

    private:
      std::function<void()> func_;
      QObject *thread_{nullptr};
    };

    struct sleep_awaiter : std::suspend_always
    {
      explicit sleep_awaiter(int duration_ms)
        : duration_ms_(duration_ms)
      {
      }

      void await_suspend(std::coroutine_handle<> h)
      {
        handle_ = h;
        // TODO: this only works for a Qt thread
        QTimer::singleShot(duration_ms_, [this]() { handle_.resume(); });
      }

    private:
      std::coroutine_handle<> handle_;
      int duration_ms_;
    };

    class scheduler
    {
    public:
      template<typename ValueType>
      using qtask = unfold::coro::task<ValueType, qt::scheduler>;
      using executer = executer;

      explicit scheduler(QObject *thread, boost::asio::io_context *ioc)
        : thread_(thread)
        , ioc_(ioc)
      {
      }

      ~scheduler() = default;

      auto get_executor() const
      {
        return executer(thread_);
      }

      void spawn(qtask<void> &&task)
      {
        task.set_scheduler(this);
        task.set_io_context(ioc_);
        auto exec{std::make_shared<unfold::coro::qt::executer>(thread_)};
        exec->execute([exec, task = std::move(task)]() mutable { task.resume(); });
      }

      auto sleep(int duration_ms)
      {
        return sleep_awaiter{duration_ms};
      }

    private:
      QObject *thread_{nullptr};
      boost::asio::io_context *ioc_{nullptr};
    };

  } // namespace qt

  template<typename ValueType>
  using qttask = unfold::coro::task<ValueType, qt::scheduler>;

} // namespace unfold::coro

#endif // UNFOLD_CORO_QTTASK_HH
