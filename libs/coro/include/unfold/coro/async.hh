#include <cassert>
#include <future>
#include <iostream>
#include <optional>
#include <thread>

using namespace std::literals;

#include "coro.hh"

template<class T>
class FutureAwaitable
{
public:
  template<class U>
  struct BasicPromiseType
  {
    auto get_return_object()
    {
      return FutureAwaitable<T>(CoroHandle::from_promise(*this));
    }

    std::suspend_always initial_suspend() noexcept
    {
      std::cout << "Initial suspend\n";
      return {};
    }

    std::suspend_never final_suspend() noexcept
    {
      std::cout << "Final suspend\n";
      return {};
    }

    template<class V>
    requires std::is_convertible_v<V, T>
    void return_value(V v)
    {
      _value = v;
    }

    void unhandled_exception()
    {
      throw;
    }

    std::optional<T> _value;
  };

  using promise_type = BasicPromiseType<FutureAwaitable<T>>;
  using CoroHandle = std::coroutine_handle<promise_type>;

  explicit FutureAwaitable(CoroHandle h)
    : _parent(h)
  {
  }

  ~FutureAwaitable()
  {
  }

  bool is_ready() const
  {
    auto &fut = std::get<FutureAwaitable<T> *>(&_parent);
    return fut->wait_for(std::chrono::seconds(0)) != std::future_status::ready;
  }

  FutureAwaitable(std::future<T> &&f)
  {
    _f = &f;
  }

  T get() const
  {
    return promise()._value.value();
  }

  std::future<T> &std_future() const
  {
    assert(_f->valid());
    return *_f;
  }

  bool await_ready()
  {
    if (!(_f->wait_for(std::chrono::seconds(0)) == std::future_status::ready))
      {
        std::cout << "Await ready IS ready\n";
        return true;
      }

    std::cout << "Await ready NOT ready\n";

    return false;
  }

  auto await_resume()
  {
    std::cout << "Await resume" << std::endl;
    return std_future().get();
  }

  bool await_suspend(CoroHandle parent)
  {
    _parent = parent;
    std::cout << "Await suspend\n";
    return true;
  }

  void resume()
  {
    assert(_parent);
    _parent.resume();
  }

  auto parent() const
  {
    return _parent;
  }

  bool done() const noexcept
  {
    return _parent.done();
  }

private:
  auto &promise() const noexcept
  {
    return _parent.promise();
  }

  CoroHandle _parent = nullptr;
  std::future<T> *_f = nullptr;
};

template<class T>
auto operator co_await(std::future<T> &&f)
{
  return FutureAwaitable<T>(std::forward<std::future<T>>(f));
}

template<class T>
auto operator co_await(std::future<T> &f)
{
  return FutureAwaitable<T>(std::forward<std::future<T>>(f));
}

FutureAwaitable<int>
coroutine()
{
  std::promise<int> p;
  auto fut = p.get_future();
  p.set_value(31);
  std::cout << "Entered func()" << std::endl;
  auto res = co_await std::move(fut);
  std::cout << "Continue func(): " << res << std::endl;

  auto computation = co_await std::async(std::launch::async, [] {
    int j = 0;
    for (int i = 0; i < 1000; ++i)
      {
        j += i;
      }
    return j;
  });

  auto computation2 = std::async(std::launch::async, [] {
    int j = 0;
    std::this_thread::sleep_for(20s);
    for (int i = 0; i < 1000; ++i)
      {
        j += i;
      }
    return j;
  });

  auto computation3 = std::async(std::launch::async, [] {
    int j = 0;
    std::this_thread::sleep_for(20s);
    for (int i = 0; i < 1000; ++i)
      {
        j += i;
      }
    return j;
  });
  co_await computation2;
  co_await computation3;

  std::cout << "Computation result is " << computation << std::endl;
  co_return computation;
}

#define ASYNC_MAIN(coro)                               \
  int main()                                           \
  {                                                    \
    FutureAwaitable<int> c = coro();                   \
    do                                                 \
      {                                                \
        c.resume();                                    \
      }                                                \
    while (!c.done());                                 \
    std::cout << "The coroutine returned " << c.get(); \
    return 0;                                          \
  }

ASYNC_MAIN(coroutine)
