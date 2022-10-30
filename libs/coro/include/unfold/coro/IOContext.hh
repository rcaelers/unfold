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

#ifndef UNFOLD_CORO_IO_CONTEXT_HH
#define UNFOLD_CORO_IO_CONTEXT_HH

#include <boost/asio/io_context.hpp>
#include <thread>
#include <latch>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include <boost/asio.hpp>

namespace unfold::coro
{
  class IOContext
  {
  public:
    IOContext();
    ~IOContext();

    boost::asio::io_context *get_io_context();
    void stop();
    void wait();

    IOContext(const IOContext &) = delete;
    IOContext &operator=(const IOContext &) = delete;
    IOContext(IOContext &&) = delete;
    IOContext &operator=(IOContext &&) = delete;

  private:
    static constexpr int num_threads{1};
    boost::asio::io_context ioc_;
    std::latch sync_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard_;
    std::vector<std::thread> workers_;
  };
} // namespace unfold::coro

#endif // UNFOLD_CORO_IO_CONTEXT_HH
