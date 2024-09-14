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

#include <boost/test/tools/old/interface.hpp>
#include <memory>
#include <fstream>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#if SPDLOG_VERSION >= 10600
#  include <spdlog/pattern_formatter.h>
#endif
#if SPDLOG_VERSION >= 10801
#  include <spdlog/cfg/env.h>
#endif

#include "utils/Logging.hh"
#include "utils/StringUtils.hh"
#include "utils/DateUtils.hh"
#include "utils/Base64.hh"

#define BOOST_TEST_MODULE "unfold"
#include <boost/test/unit_test.hpp>

using namespace unfold::utils;

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
    const auto *log_file = "unfold-test-utils.log";

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

struct Fixture
{
  Fixture() = default;
  ~Fixture() = default;

  Fixture(const Fixture &) = delete;
  Fixture &operator=(const Fixture &) = delete;
  Fixture(Fixture &&) = delete;
  Fixture &operator=(Fixture &&) = delete;

private:
  std::shared_ptr<spdlog::logger> logger{Logging::create("test")};
};

BOOST_TEST_GLOBAL_FIXTURE(GlobalFixture);

BOOST_FIXTURE_TEST_SUITE(unfold_test, Fixture)

BOOST_AUTO_TEST_CASE(utils_string_utf16_to_utf8)
{
  std::string s = unfold::utils::utf16_to_utf8(L"Hello World");
  BOOST_CHECK_EQUAL(s, "Hello World");
}

BOOST_AUTO_TEST_CASE(utils_string_utf8_to_utf16)
{
  std::wstring s = unfold::utils::utf8_to_utf16("Hello World");
  BOOST_CHECK(s == L"Hello World");
}

BOOST_AUTO_TEST_CASE(utils_empty_string_utf16_to_utf8)
{
  std::string s = unfold::utils::utf16_to_utf8(L"");
  BOOST_CHECK_EQUAL(s, "");
}

BOOST_AUTO_TEST_CASE(utils_empty_string_utf8_to_utf16)
{
  std::wstring s = unfold::utils::utf8_to_utf16("");
  BOOST_CHECK(s == L"");
}

BOOST_AUTO_TEST_CASE(utils_base64_encode)
{
  std::string s = unfold::utils::Base64::encode("Hello World");
  BOOST_CHECK_EQUAL(s, "SGVsbG8gV29ybGQ=");
}

BOOST_AUTO_TEST_CASE(utils_base64_decode)
{
  std::string s = unfold::utils::Base64::decode("SGVsbG8gV29ybGQ=");
  BOOST_CHECK_EQUAL(s, "Hello World");
}

BOOST_AUTO_TEST_CASE(utils_base64_decode_0_terminated)
{
  std::string ref = {'\xe3', '\xeb', '\x54', '\x77', '\x79', '\x46', '\xba', '\x72', '\xfa', '\x85', '\x96', '\x60', '\x02',
                     '\x31', '\xb5', '\x85', '\xea', '\xe6', '\xaf', '\x8c', '\x43', '\x18', '\xf3', '\x5e', '\xaa', '\x52',
                     '\x0f', '\x40', '\xfb', '\xdd', '\xe2', '\x4f', '\xdc', '\xdd', '\x4c', '\xad', '\x19', '\x9d', '\x22',
                     '\x1f', '\xd4', '\x24', '\xb2', '\xbb', '\x2e', '\x27', '\xb3', '\x0d', '\xc3', '\xa5', '\xfc', '\x1c',
                     '\x76', '\xaf', '\x76', '\x10', '\xb0', '\xc5', '\xed', '\x83', '\x43', '\x3b', '\x55', '\x00'};

  std::string decoded = unfold::utils::Base64::decode(
    "4+tUd3lGunL6hZZgAjG1hermr4xDGPNeqlIPQPvd4k/c3UytGZ0iH9QksrsuJ7MNw6X8HHavdhCwxe2DQztVAA==");

  BOOST_CHECK_EQUAL(decoded.size(), 64);
  BOOST_CHECK_EQUAL(decoded, ref);
}

BOOST_AUTO_TEST_CASE(utils_base64_encode_0_terminated)
{
  std::string ref = "4+tUd3lGunL6hZZgAjG1hermr4xDGPNeqlIPQPvd4k/c3UytGZ0iH9QksrsuJ7MNw6X8HHavdhCwxe2DQztVAA==";

  std::string decoded = {'\xe3', '\xeb', '\x54', '\x77', '\x79', '\x46', '\xba', '\x72', '\xfa', '\x85', '\x96', '\x60', '\x02',
                         '\x31', '\xb5', '\x85', '\xea', '\xe6', '\xaf', '\x8c', '\x43', '\x18', '\xf3', '\x5e', '\xaa', '\x52',
                         '\x0f', '\x40', '\xfb', '\xdd', '\xe2', '\x4f', '\xdc', '\xdd', '\x4c', '\xad', '\x19', '\x9d', '\x22',
                         '\x1f', '\xd4', '\x24', '\xb2', '\xbb', '\x2e', '\x27', '\xb3', '\x0d', '\xc3', '\xa5', '\xfc', '\x1c',
                         '\x76', '\xaf', '\x76', '\x10', '\xb0', '\xc5', '\xed', '\x83', '\x43', '\x3b', '\x55', '\x00'};

  std::string encoded = unfold::utils::Base64::encode(decoded);

  BOOST_CHECK_EQUAL(encoded, ref);
}

BOOST_AUTO_TEST_CASE(utils_dateutils_rfc)
{
  std::string date_str_rfc = "Wed, 13 Sep 2023 15:35:22 +0000";
  std::chrono::system_clock::time_point tp = unfold::utils::DateUtils::parse_time_point(date_str_rfc);

  std::time_t time = std::chrono::system_clock::to_time_t(tp);
  std::tm *tm = std::gmtime(&time);

  BOOST_CHECK_EQUAL(tm->tm_year + 1900, 2023);
  BOOST_CHECK_EQUAL(tm->tm_mon + 1, 9);
  BOOST_CHECK_EQUAL(tm->tm_mday, 13);
  BOOST_CHECK_EQUAL(tm->tm_hour, 15);
  BOOST_CHECK_EQUAL(tm->tm_min, 35);
  BOOST_CHECK_EQUAL(tm->tm_sec, 22);
}

BOOST_AUTO_TEST_CASE(utils_dateutils_rfc_tz)
{
  std::string date_str_rfc = "Wed, 13 Sep 2023 15:35:22 +0200";
  std::chrono::system_clock::time_point tp = unfold::utils::DateUtils::parse_time_point(date_str_rfc);

  std::time_t time = std::chrono::system_clock::to_time_t(tp);
  std::tm *tm = std::gmtime(&time);

  BOOST_CHECK_EQUAL(tm->tm_year + 1900, 2023);
  BOOST_CHECK_EQUAL(tm->tm_mon + 1, 9);
  BOOST_CHECK_EQUAL(tm->tm_mday, 13);
  BOOST_CHECK_EQUAL(tm->tm_hour, 15);
  BOOST_CHECK_EQUAL(tm->tm_min, 35);
  BOOST_CHECK_EQUAL(tm->tm_sec, 22);
}

BOOST_AUTO_TEST_CASE(utils_dateutils_iso)
{
  std::string date_str_rfc = "2023-09-13T15:35:22Z";
  std::chrono::system_clock::time_point tp = unfold::utils::DateUtils::parse_time_point(date_str_rfc);

  std::time_t time = std::chrono::system_clock::to_time_t(tp);
  std::tm *tm = std::gmtime(&time);

  BOOST_CHECK_EQUAL(tm->tm_year + 1900, 2023);
  BOOST_CHECK_EQUAL(tm->tm_mon + 1, 9);
  BOOST_CHECK_EQUAL(tm->tm_mday, 13);
  BOOST_CHECK_EQUAL(tm->tm_hour, 15);
  BOOST_CHECK_EQUAL(tm->tm_min, 35);
  BOOST_CHECK_EQUAL(tm->tm_sec, 22);
}

BOOST_AUTO_TEST_CASE(utils_dateutils_iso_np_z)
{
  std::string date_str_rfc = "2023-09-13T15:35:22";
  std::chrono::system_clock::time_point tp = unfold::utils::DateUtils::parse_time_point(date_str_rfc);

  std::time_t time = std::chrono::system_clock::to_time_t(tp);
  std::tm *tm = std::gmtime(&time);

  BOOST_CHECK_EQUAL(tm->tm_year + 1900, 2023);
  BOOST_CHECK_EQUAL(tm->tm_mon + 1, 9);
  BOOST_CHECK_EQUAL(tm->tm_mday, 13);
  BOOST_CHECK_EQUAL(tm->tm_hour, 15);
  BOOST_CHECK_EQUAL(tm->tm_min, 35);
  BOOST_CHECK_EQUAL(tm->tm_sec, 22);
}

BOOST_AUTO_TEST_CASE(utils_dateutils_incorrect_date)
{
  std::string date_str_rfc = "2023-13-13T15:35:22";
  BOOST_CHECK_THROW(unfold::utils::DateUtils::parse_time_point(date_str_rfc), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
