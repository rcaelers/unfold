#include <iostream>
#include <exception>
#include <thread>
#include <chrono>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>
#include <boost/outcome/std_result.hpp>

#include "unfold/coro/task.hh"
#include "unfold/coro/gtask.hh"
#include "http/HttpClient.hh"
#include "http/HttpClientErrors.hh"
#include "unfold/coro/IOContext.hh"

#include <glib.h>
#include <glib-object.h>

namespace outcome = boost::outcome_v2;

static GMainContext *context = NULL;
static GMainLoop *loop = NULL;

template<typename DurationT>
auto
sleep(const DurationT &d)
{

  struct awaitable : std::suspend_always
  {
    DurationT duration_;

    explicit awaitable(const DurationT &duration)
      : duration_(duration)
    {
    }

    static gboolean on_timer_callback(gpointer data)
    {
      spdlog::info("sleep awaitable: on_timer");
      auto *x = static_cast<awaitable *>(data);
      x->co.resume();
      return FALSE;
    }

    void await_suspend(std::coroutine_handle<> h)
    {
      spdlog::info("sleep awaitable: await_suspend");
      co = h;
      GSource *source = g_timeout_source_new_seconds(10);
      g_source_set_callback(source, on_timer_callback, this, nullptr);
      g_source_attach(source, context);
      g_source_unref(source);
    }

    std::coroutine_handle<> co;
  };

  spdlog::info("sleep");
  return awaitable{d};
}

boost::asio::awaitable<outcome::std_result<std::string>>
download_appcast()
{
  auto http = std::make_shared<unfold::http::HttpClient>();

  auto rc = co_await http->get("https://snapshots.workrave.org/snapshots/v1.11/testappcast.xml");

  if (rc.has_error())
    {
      spdlog::info("failed to download appcast ({})", rc.error());
      co_return unfold::http::HttpClientErrc::InternalError;
    }

  auto [result, content] = rc.value();
  if (result != 200)
    {
      spdlog::info("failed to download appcast ({} {})", result, content);
      co_return unfold::http::HttpClientErrc::InternalError;
    }

  if (content.empty())
    {
      spdlog::info("failed to download appcast (empty)");
      co_return unfold::http::HttpClientErrc::InternalError;
    }

  co_return content;
}

unfold::coro::gtask<int>
sub_task1()
{
  using namespace std::literals::chrono_literals;
  spdlog::info("subtaskl 1 begin");
  auto s = co_await download_appcast();
  // co_await sleep(1000ms);
  spdlog::info("subtaskl 1 end {}", s.value());
  co_return 42;
}

unfold::coro::gtask<void>
sub_task2()
{
  spdlog::info("subtaskl 2 begin");
  co_return;
}

unfold::coro::gtask<void>
main_task()
{
  spdlog::info("maintask begin");
  auto i = co_await sub_task1();
  spdlog::info("maintask end {}", i);
  co_return;
}

static gboolean
on_timer_callback(gpointer data)
{
  static guint16 i = 0;
  spdlog::info("on timer {}", i++);
  return TRUE;
}

int
main(int argc, char **argv)
{
  (void)argc;
  (void)argv;

  context = g_main_context_new();
  loop = g_main_loop_new(context, TRUE);

  unfold::coro::IOContext io_context;

  unfold::coro::gtask<void> task = main_task();
  unfold::coro::glib::scheduler s{context, io_context.get_io_context()};

  s.spawn(std::move(task));

  GSource *source = g_timeout_source_new_seconds(1);
  g_source_set_callback(source, on_timer_callback, loop, nullptr);
  g_source_attach(source, context);
  g_source_unref(source);

  spdlog::info("main loop begin");
  g_main_loop_run(loop);
  spdlog::info("main loop end");
  g_main_loop_unref(loop);
  g_main_context_unref(context);
}
