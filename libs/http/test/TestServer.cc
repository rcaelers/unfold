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

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#if SPDLOG_VERSION >= 10600
#  include <spdlog/pattern_formatter.h>
#endif
#if SPDLOG_VERSION >= 10801
#  include <spdlog/cfg/env.h>
#endif

#include "http/HttpServer.hh"

static void
setup_loggin()
{
  const auto *log_file = "unfold-test.log";

  auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file, false);
  auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

  auto logger{std::make_shared<spdlog::logger>("unfold", std::initializer_list<spdlog::sink_ptr>{file_sink, console_sink})};
  logger->flush_on(spdlog::level::critical);
  spdlog::set_default_logger(logger);

  spdlog::set_level(spdlog::level::info);
  spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%-5l%$] %v");

#if SPDLOG_VERSION >= 10801
  spdlog::cfg::load_env_levels();
#endif
}

int
main(int argc, char **argv)
{
  setup_loggin();

  unfold::http::HttpServer server_secure;
  server_secure.add("/foo", "foo\n");
  server_secure.run();

  unfold::http::HttpServer server_plain1(unfold::http::Protocol::Plain, 1338);
  server_plain1.add("/bar", "bat\n");
  server_plain1.run();

  unfold::http::HttpServer server_plain2(unfold::http::Protocol::Plain, 1339);
  server_plain2.add("/baz", "baz\n");
  server_plain2.run();

  while (true)
    {
      sleep(1);
    }
}
