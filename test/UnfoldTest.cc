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

#define BOOST_TEST_MODULE "unfold"
#include <boost/test/unit_test.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#if SPDLOG_VERSION >= 10600
#  include <spdlog/pattern_formatter.h>
#endif
#if SPDLOG_VERSION >= 10801
#  include <spdlog/cfg/env.h>
#endif
#include <spdlog/fmt/ostr.h>

#include "TestBase.hh"
#include "unfold/UnfoldErrors.hh"
#include "UnfoldInternalErrors.hh"

struct GlobalFixture
{
  GlobalFixture() = default;
  ~GlobalFixture() = default;

  GlobalFixture(const GlobalFixture &) = delete;
  GlobalFixture &operator=(const GlobalFixture &) = delete;
  GlobalFixture(GlobalFixture &&) = delete;
  GlobalFixture &operator=(GlobalFixture &&) = delete;

  void setup()
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

private:
};

BOOST_TEST_GLOBAL_FIXTURE(GlobalFixture);

BOOST_FIXTURE_TEST_SUITE(unfold_test, Fixture)

BOOST_AUTO_TEST_CASE(unfold_error_code)
{
  auto error = unfold::make_error_code(unfold::UnfoldErrc::InternalError);
  BOOST_CHECK_EQUAL(error.message(), "internal error");
  BOOST_CHECK_EQUAL(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::AppcastDownloadFailed);
  BOOST_CHECK_EQUAL(error.message(), "failed to download appcast");
  BOOST_CHECK_EQUAL(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::InstallerDownloadFailed);
  BOOST_CHECK_EQUAL(error.message(), "failed to download installer");
  BOOST_CHECK_EQUAL(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::InstallerExecutionFailed);
  BOOST_CHECK_EQUAL(error.message(), "failed to execute installer");
  BOOST_CHECK_EQUAL(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::InstallerVerificationFailed);
  BOOST_CHECK_EQUAL(error.message(), "failed to validate installer integrity");
  BOOST_CHECK_EQUAL(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::InvalidAppcast);
  BOOST_CHECK_EQUAL(error.message(), "invalid appcast");
  BOOST_CHECK_EQUAL(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::InvalidArgument);
  BOOST_CHECK_EQUAL(error.message(), "invalid argument");
  BOOST_CHECK_EQUAL(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::Success);
  BOOST_CHECK_EQUAL(error.message(), "success");
  BOOST_CHECK_EQUAL(error.category().name(), "unfold");
}

BOOST_AUTO_TEST_CASE(unfold_internal_error_code)
{
  auto error = make_error_code(UnfoldInternalErrc::InternalError);
  BOOST_CHECK_EQUAL(error.message(), "internal error");
  BOOST_CHECK_EQUAL(error.category().name(), "unfold");

  error = make_error_code(UnfoldInternalErrc::InvalidSetting);
  BOOST_CHECK_EQUAL(error.message(), "invalid setting");
  BOOST_CHECK_EQUAL(error.category().name(), "unfold");

  error = make_error_code(UnfoldInternalErrc::Success);
  BOOST_CHECK_EQUAL(error.message(), "success");
  BOOST_CHECK_EQUAL(error.category().name(), "unfold");
}

BOOST_AUTO_TEST_SUITE_END()
