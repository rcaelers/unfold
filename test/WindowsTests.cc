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

#include <boost/test/unit_test.hpp>
#include <spdlog/spdlog.h>

#include "unfold/Unfold.hh"
#include "unfold/UnfoldErrors.hh"

#include "windows/WindowsSettingsStorage.hh"

#include "SignatureVerifierMock.hh"
#include "Fixture.hpp"

BOOST_FIXTURE_TEST_SUITE(unfold_windows_test, Fixture)

BOOST_AUTO_TEST_CASE(windows_settings_string)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  rc = storage.remove_key("foo");

  auto s = storage.get_value("foo", SettingType::String);
  BOOST_CHECK_EQUAL(s.has_value(), false);
  rc = storage.set_value("foo", "bar");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::String);
  BOOST_CHECK_EQUAL(s.has_value(), true);
  BOOST_CHECK_EQUAL(std::get<std::string>(s.value()), "bar");
  BOOST_CHECK_EQUAL(SettingValueToType(s.value()), SettingType::String);
}

BOOST_AUTO_TEST_CASE(windows_settings_int64)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  rc = storage.remove_key("foo");

  auto s = storage.get_value("foo", SettingType::Int64);
  BOOST_CHECK_EQUAL(s.has_value(), false);
  rc = storage.set_value("foo", 42LL);
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Int64);
  BOOST_CHECK_EQUAL(s.has_value(), true);
  BOOST_CHECK_EQUAL(std::get<int64_t>(s.value()), 42LL);
  BOOST_CHECK_EQUAL(SettingValueToType(s.value()), SettingType::Int64);
}

BOOST_AUTO_TEST_CASE(windows_settings_int32)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  rc = storage.remove_key("foo");

  auto s = storage.get_value("foo", SettingType::Int32);
  BOOST_CHECK_EQUAL(s.has_value(), false);
  rc = storage.set_value("foo", 43);
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Int32);
  BOOST_CHECK_EQUAL(s.has_value(), true);
  BOOST_CHECK_EQUAL(std::get<int32_t>(s.value()), 43);
  BOOST_CHECK_EQUAL(SettingValueToType(s.value()), SettingType::Int32);
}

BOOST_AUTO_TEST_CASE(windows_settings_bool)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  rc = storage.remove_key("foo");

  auto s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_value(), false);
  rc = storage.set_value("foo", true);
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_value(), true);
  BOOST_CHECK_EQUAL(std::get<bool>(s.value()), true);
  rc = storage.set_value("foo", false);
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_value(), true);
  BOOST_CHECK_EQUAL(std::get<bool>(s.value()), false);
  BOOST_CHECK_EQUAL(SettingValueToType(s.value()), SettingType::Boolean);
}

BOOST_AUTO_TEST_CASE(windows_settings_remove)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  rc = storage.remove_key("foo");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  rc = storage.remove_key("\n");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
}

BOOST_AUTO_TEST_CASE(windows_settings_invalid_subkey)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("\\\\");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  auto s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value("foo", SettingType::Int32);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value("foo", SettingType::Int64);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value("foo", SettingType::String);
  BOOST_CHECK_EQUAL(s.has_error(), true);

  rc = storage.remove_key("foo");
  BOOST_CHECK_EQUAL(rc.has_error(), true);

  rc = storage.set_value("foo", true);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value("foo", false);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value("foo", "bar");
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value("foo", 42);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value("foo", 42LL);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
}

namespace
{
  auto very_long_string = std::string(20 * 1024, 'a');
}

BOOST_AUTO_TEST_CASE(windows_settings_get_invalid_key)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  auto s = storage.get_value("foo", SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::Boolean);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::String);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::Int32);
  BOOST_CHECK_EQUAL(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::Int64);
  BOOST_CHECK_EQUAL(s.has_error(), true);

  rc = storage.remove_key(very_long_string);
  BOOST_CHECK_EQUAL(rc.has_error(), false); // Windows return "no such key"
}

BOOST_AUTO_TEST_CASE(windows_settings_set_invalid_key)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  BOOST_CHECK_EQUAL(rc.has_error(), false);
  rc = storage.set_value(very_long_string, true);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value(very_long_string, false);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value(very_long_string, "bar");
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value(very_long_string, 42);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  rc = storage.set_value(very_long_string, 42LL);
  BOOST_CHECK_EQUAL(rc.has_error(), true);
}

BOOST_AUTO_TEST_SUITE_END()
