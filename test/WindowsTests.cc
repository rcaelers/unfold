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

#include "windows/WindowsSettingsStorage.hh"
#include "windows/WindowsPlatform.hh"

TEST(Windows, windows_settings_string)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  EXPECT_EQ(rc.has_error(), false);
  rc = storage.remove_key("foo");

  auto s = storage.get_value("foo", SettingType::String);
  EXPECT_EQ(s.has_value(), false);
  rc = storage.set_value("foo", "bar");
  EXPECT_EQ(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::String);
  EXPECT_EQ(s.has_value(), true);
  EXPECT_EQ(std::get<std::string>(s.value()), "bar");
  EXPECT_EQ(SettingValueToType(s.value()), SettingType::String);
}

TEST(Windows, windows_settings_int64)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  EXPECT_EQ(rc.has_error(), false);
  rc = storage.remove_key("foo");

  auto s = storage.get_value("foo", SettingType::Int64);
  EXPECT_EQ(s.has_value(), false);
  rc = storage.set_value("foo", 42LL);
  EXPECT_EQ(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Int64);
  EXPECT_EQ(s.has_value(), true);
  EXPECT_EQ(std::get<int64_t>(s.value()), 42LL);
  EXPECT_EQ(SettingValueToType(s.value()), SettingType::Int64);
}

TEST(Windows, windows_settings_int32)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  rc = storage.remove_key("foo");

  auto s = storage.get_value("foo", SettingType::Int32);
  EXPECT_EQ(s.has_value(), false);
  rc = storage.set_value("foo", 43);
  EXPECT_EQ(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Int32);
  EXPECT_EQ(s.has_value(), true);
  EXPECT_EQ(std::get<int32_t>(s.value()), 43);
  EXPECT_EQ(SettingValueToType(s.value()), SettingType::Int32);
}

TEST(Windows, windows_settings_bool)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  rc = storage.remove_key("foo");

  auto s = storage.get_value("foo", SettingType::Boolean);
  EXPECT_EQ(s.has_value(), false);
  rc = storage.set_value("foo", true);
  EXPECT_EQ(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Boolean);
  EXPECT_EQ(s.has_value(), true);
  EXPECT_EQ(std::get<bool>(s.value()), true);
  rc = storage.set_value("foo", false);
  EXPECT_EQ(rc.has_error(), false);
  s = storage.get_value("foo", SettingType::Boolean);
  EXPECT_EQ(s.has_value(), true);
  EXPECT_EQ(std::get<bool>(s.value()), false);
  EXPECT_EQ(SettingValueToType(s.value()), SettingType::Boolean);
}

TEST(Windows, windows_settings_remove)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  EXPECT_EQ(rc.has_error(), false);
  rc = storage.remove_key("foo");
  EXPECT_EQ(rc.has_error(), false);
  rc = storage.remove_key("\n");
  EXPECT_EQ(rc.has_error(), false);
}

TEST(Windows, windows_settings_invalid_subkey)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("\\\\");
  EXPECT_EQ(rc.has_error(), false);

  auto s = storage.get_value("foo", SettingType::Boolean);
  EXPECT_EQ(s.has_error(), true);
  s = storage.get_value("foo", SettingType::Boolean);
  EXPECT_EQ(s.has_error(), true);
  s = storage.get_value("foo", SettingType::Int32);
  EXPECT_EQ(s.has_error(), true);
  s = storage.get_value("foo", SettingType::Int64);
  EXPECT_EQ(s.has_error(), true);
  s = storage.get_value("foo", SettingType::String);
  EXPECT_EQ(s.has_error(), true);

  rc = storage.remove_key("foo");
  EXPECT_EQ(rc.has_error(), true);

  rc = storage.set_value("foo", true);
  EXPECT_EQ(rc.has_error(), true);
  rc = storage.set_value("foo", false);
  EXPECT_EQ(rc.has_error(), true);
  rc = storage.set_value("foo", "bar");
  EXPECT_EQ(rc.has_error(), true);
  rc = storage.set_value("foo", 42);
  EXPECT_EQ(rc.has_error(), true);
  rc = storage.set_value("foo", 42LL);
  EXPECT_EQ(rc.has_error(), true);
}

namespace
{
  auto very_long_string = std::string(20 * 1024, 'a');
}

TEST(Windows, windows_settings_get_invalid_key)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  EXPECT_EQ(rc.has_error(), false);
  auto s = storage.get_value("foo", SettingType::Boolean);
  EXPECT_EQ(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::Boolean);
  EXPECT_EQ(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::String);
  EXPECT_EQ(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::Int32);
  EXPECT_EQ(s.has_error(), true);
  s = storage.get_value(very_long_string, SettingType::Int64);
  EXPECT_EQ(s.has_error(), true);

  rc = storage.remove_key(very_long_string);
  EXPECT_EQ(rc.has_error(), false); // Windows return "no such key"
}

TEST(Windows, windows_settings_set_invalid_key)
{
  WindowsSettingsStorage storage;

  auto rc = storage.set_prefix("Software\\UnfoldTest");
  EXPECT_EQ(rc.has_error(), false);
  rc = storage.set_value(very_long_string, true);
  EXPECT_EQ(rc.has_error(), true);
  rc = storage.set_value(very_long_string, false);
  EXPECT_EQ(rc.has_error(), true);
  rc = storage.set_value(very_long_string, "bar");
  EXPECT_EQ(rc.has_error(), true);
  rc = storage.set_value(very_long_string, 42);
  EXPECT_EQ(rc.has_error(), true);
  rc = storage.set_value(very_long_string, 42LL);
  EXPECT_EQ(rc.has_error(), true);
}

TEST(Windows, windows_platform_is_supported)
{
  WindowsPlatform platform;

  auto rc = platform.is_supported_os("foo");
  EXPECT_EQ(rc, false);
  rc = platform.is_supported_os("windows");
  EXPECT_EQ(rc, true);
  rc = platform.is_supported_os("linux");
  EXPECT_EQ(rc, false);
  rc = platform.is_supported_os("macos");
  EXPECT_EQ(rc, false);

  auto rc32 = platform.is_supported_os("windows-x86");
  auto rc64 = platform.is_supported_os("windows-x64");
#ifdef _WIN64
  EXPECT_EQ(rc32, false);
  EXPECT_EQ(rc64, true);
#else
  EXPECT_EQ(rc32, true);
  EXPECT_EQ(rc64, false);
#endif
}

// TEST(Windows, windows_platform_is_supported_os_version)
// {
//   WindowsPlatform platform;

//   auto rc = platform.is_supported_os_version("");
//   EXPECT_EQ(rc, true);

//   rc = platform.is_supported_os_version("9.0.0");
//   EXPECT_EQ(rc, true);

//   rc = platform.is_supported_os_version("10.0.0");
//   EXPECT_EQ(rc, true);

//   rc = platform.is_supported_os_version("12.0.0");
//   EXPECT_EQ(rc, false);
// }
