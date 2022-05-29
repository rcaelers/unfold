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

#ifndef CORO_GTASK_HH
#define CORO_GTASK_HH

#include <exception>
#include <memory>
#include <utility>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include <glib.h>
#include <glib-object.h>

#include "coro.hh"
#include "coro/task.hh"

namespace unfold::coro
{
  namespace glib
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
      explicit executer(GMainContext *context)
        : context_(context)
      {
      }

      ~executer() = default;

      executer(const executer &) = delete;
      executer &operator=(const executer &) = delete;

      executer(executer &&other) noexcept
        : context_(std::exchange(other.context_, nullptr))
      {
      }

      auto operator=(executer &&other) noexcept -> executer &
      {
        if (std::addressof(other) != this)
          {
            context_ = std::exchange(other.context_, nullptr);
          }

        return *this;
      }

      void execute(auto f)
      {
        func_ = detail::make_function(std::move(f));
        GSource *idle_source = g_idle_source_new();
        g_source_set_callback(idle_source, on_resume_coroutine, this, nullptr);
        g_source_attach(idle_source, context_);
        g_source_unref(idle_source);
      }

    private:
      static gboolean on_resume_coroutine(gpointer data)
      {
        auto *self = static_cast<executer *>(data);
        self->func_();
        return FALSE;
      }

    private:
      std::function<void()> func_;
      GMainContext *context_;
    };

    struct sleep_awaiter : std::suspend_always
    {
      sleep_awaiter(guint duration, GMainContext *context)
        : duration_(duration)
        , context_(context)
      {
      }

      static gboolean on_timer_callback(gpointer data)
      {
        auto *self = static_cast<sleep_awaiter *>(data);
        self->handle_.resume();
        return FALSE;
      }

      void await_suspend(std::coroutine_handle<> h)
      {
        handle_ = h;
        GSource *source = g_timeout_source_new_seconds(duration_);
        g_source_set_callback(source, on_timer_callback, this, nullptr);
        g_source_attach(source, context_);
        g_source_unref(source);
      }

    private:
      std::coroutine_handle<> handle_;
      guint duration_;
      GMainContext *context_;
    };

    class scheduler
    {
    public:
      template<typename ValueType>
      using gtask = unfold::coro::task<ValueType, glib::scheduler>;
      using executer = executer;

      explicit scheduler(GMainContext *context)
        : context_(context)
      {
      }

      ~scheduler() = default;

      auto get_executor() const
      {
        return executer(context_);
      }

      void spawn(gtask<void> &&task)
      {
        task.set_scheduler(this);
        auto exec{std::make_shared<unfold::coro::glib::executer>(context_)};
        exec->execute([exec, task = std::move(task)]() mutable { task.resume(); });
      }

      auto sleep(guint duration)
      {
        return sleep_awaiter{duration, context_};
      }

    private:
      GMainContext *context_{nullptr};
    };

  } // namespace glib

  template<typename ValueType>
  using gtask = unfold::coro::task<ValueType, glib::scheduler>;

} // namespace unfold::coro

#endif // GLIB_SCHEDULER_HH
