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

#include "unfold/coro/IOContext.hh"

#include <spdlog/spdlog.h>

using namespace unfold::coro;

IOContext::IOContext(int num_threads)
  : ioc_(num_threads)
  , sync_(num_threads)
  , guard_(boost::asio::make_work_guard(ioc_))
{
  workers_.reserve(num_threads);
  for (auto i = 0; i < num_threads; i++)
    {
      workers_.emplace_back([this] {
        ioc_.run();
        sync_.count_down();
      });
    }
}

IOContext::~IOContext()
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

boost::asio::io_context *
IOContext::get_io_context()
{
  return &ioc_;
}

void
IOContext::stop()
{
  ioc_.stop();
}

void
IOContext::wait()
{
  sync_.wait();
}
