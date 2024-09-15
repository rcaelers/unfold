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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

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

#include "unfold/UnfoldErrors.hh"
#include "UnfoldInternalErrors.hh"

class GlobalFixture : public ::testing::Environment
{
public:
  void SetUp() override
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

  void TearDown() override
  {
    spdlog::drop_all();
  }
};

::testing::Environment *const global_env = ::testing::AddGlobalTestEnvironment(new GlobalFixture);

TEST(Unfold, unfold_error_code)
{
  auto error = unfold::make_error_code(unfold::UnfoldErrc::InternalError);
  EXPECT_EQ(error.message(), "internal error");
  EXPECT_STREQ(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::AppcastDownloadFailed);
  EXPECT_EQ(error.message(), "failed to download appcast");
  EXPECT_STREQ(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::InstallerDownloadFailed);
  EXPECT_EQ(error.message(), "failed to download installer");
  EXPECT_STREQ(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::InstallerExecutionFailed);
  EXPECT_EQ(error.message(), "failed to execute installer");
  EXPECT_STREQ(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::InstallerVerificationFailed);
  EXPECT_EQ(error.message(), "failed to validate installer integrity");
  EXPECT_STREQ(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::InvalidAppcast);
  EXPECT_EQ(error.message(), "invalid appcast");
  EXPECT_STREQ(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::InvalidArgument);
  EXPECT_EQ(error.message(), "invalid argument");
  EXPECT_STREQ(error.category().name(), "unfold");

  error = unfold::make_error_code(unfold::UnfoldErrc::Success);
  EXPECT_EQ(error.message(), "success");
  EXPECT_STREQ(error.category().name(), "unfold");
}

TEST(Unfold, unfold_internal_error_code)
{
  auto error = make_error_code(UnfoldInternalErrc::InternalError);
  EXPECT_EQ(error.message(), "internal error");
  EXPECT_STREQ(error.category().name(), "unfold");

  error = make_error_code(UnfoldInternalErrc::InvalidSetting);
  EXPECT_EQ(error.message(), "invalid setting");
  EXPECT_STREQ(error.category().name(), "unfold");

  error = make_error_code(UnfoldInternalErrc::Success);
  EXPECT_EQ(error.message(), "success");
  EXPECT_STREQ(error.category().name(), "unfold");
}
