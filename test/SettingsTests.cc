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

#include <boost/outcome/success_failure.hpp>
#include <chrono>
#include <spdlog/spdlog.h>
#include <string>
#include <sstream>

#include "Settings.hh"
#include "SettingsStorage.hh"
#include "SettingsStorageMock.hh"
#include "UnfoldInternalErrors.hh"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Return;

TEST(SettingsTest,  GetLastUpdateCheckTime)
{
  auto storage = std::make_shared<SettingsStorageMock>();

  EXPECT_CALL(*storage, set_prefix(_)).Times(0);
  EXPECT_CALL(*storage, remove_key(_)).Times(0);
  EXPECT_CALL(*storage, set_value(_, _)).Times(0);
  EXPECT_CALL(*storage, get_value("LastUpdateCheckTime", SettingType::Int64))
    .Times(2)
    .WillOnce(Return(outcome::success(32LL)))
    .WillOnce(Return(outcome::failure(UnfoldInternalErrc::InvalidSetting)));

  Settings settings(storage);
  auto rc = settings.get_last_update_check_time();
  EXPECT_TRUE(rc.has_value());
  EXPECT_EQ(rc.value().time_since_epoch().count(), 32);
  rc = settings.get_last_update_check_time();
  EXPECT_FALSE(rc.has_value());
}

TEST(SettingsTest,  SetLastUpdateCheckTime)
{
  auto storage = std::make_shared<SettingsStorageMock>();

  EXPECT_CALL(*storage, set_prefix(_)).Times(0);
  EXPECT_CALL(*storage, remove_key(_)).Times(0);
  EXPECT_CALL(*storage, get_value(_, _)).Times(0);
  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", SettingValue{657000000LL}))
    .Times(1)
    .WillOnce(Return(outcome::success()));
  EXPECT_CALL(*storage, set_value("LastUpdateCheckTime", SettingValue{857000000LL}))
    .Times(1)
    .WillOnce(Return(outcome::failure(UnfoldInternalErrc::InvalidSetting)));

  Settings settings(storage);
  settings.set_last_update_check_time(std::chrono::system_clock::time_point(std::chrono::seconds(657)));
  settings.set_last_update_check_time(std::chrono::system_clock::time_point(std::chrono::seconds(857)));
}

TEST(SettingsTest,  GetPeriodicUpdateCheckInterval)
{
  auto storage = std::make_shared<SettingsStorageMock>();

  EXPECT_CALL(*storage, set_prefix(_)).Times(0);
  EXPECT_CALL(*storage, remove_key(_)).Times(0);
  EXPECT_CALL(*storage, set_value(_, _)).Times(0);
  EXPECT_CALL(*storage, get_value("PeriodicUpdateCheckInterval", SettingType::Int64))
    .Times(2)
    .WillOnce(Return(outcome::success(56LL)))
    .WillOnce(Return(outcome::failure(UnfoldInternalErrc::InvalidSetting)));

  Settings settings(storage);
  auto rc = settings.get_periodic_update_check_interval();
  EXPECT_EQ(rc.count(), 56);
  rc = settings.get_periodic_update_check_interval();
  EXPECT_EQ(rc.count(), 0);
}

TEST(SettingsTest,  SetPeriodicUpdateCheckInterval)
{
  auto storage = std::make_shared<SettingsStorageMock>();

  EXPECT_CALL(*storage, set_prefix(_)).Times(0);
  EXPECT_CALL(*storage, remove_key(_)).Times(0);
  EXPECT_CALL(*storage, get_value(_, _)).Times(0);
  EXPECT_CALL(*storage, set_value("PeriodicUpdateCheckInterval", SettingValue{5678LL}))
    .Times(1)
    .WillOnce(Return(outcome::success()));
  EXPECT_CALL(*storage, set_value("PeriodicUpdateCheckInterval", SettingValue{8678LL}))
    .Times(1)
    .WillOnce(Return(outcome::failure(UnfoldInternalErrc::InvalidSetting)));

  Settings settings(storage);
  settings.set_periodic_update_check_interval(std::chrono::seconds(5678));
  settings.set_periodic_update_check_interval(std::chrono::seconds(8678));
}

TEST(SettingsTest,  GetPeriodicUpdateCheckEnabled)
{
  auto storage = std::make_shared<SettingsStorageMock>();

  EXPECT_CALL(*storage, set_prefix(_)).Times(0);
  EXPECT_CALL(*storage, remove_key(_)).Times(0);
  EXPECT_CALL(*storage, set_value(_, _)).Times(0);
  EXPECT_CALL(*storage, get_value("PeriodicUpdateCheckEnabled", SettingType::Boolean))
    .Times(3)
    .WillOnce(Return(outcome::success(true)))
    .WillOnce(Return(outcome::success(false)))
    .WillOnce(Return(outcome::failure(UnfoldInternalErrc::InvalidSetting)));

  Settings settings(storage);
  auto rc = settings.get_periodic_update_check_enabled();
  EXPECT_EQ(rc, true);
  rc = settings.get_periodic_update_check_enabled();
  EXPECT_EQ(rc, false);
  rc = settings.get_periodic_update_check_enabled();
  EXPECT_EQ(rc, false);
}

TEST(SettingsTest,  SetPeriodicUpdateCheckEnabled)
{
  auto storage = std::make_shared<SettingsStorageMock>();

  EXPECT_CALL(*storage, set_prefix(_)).Times(0);
  EXPECT_CALL(*storage, remove_key(_)).Times(0);
  EXPECT_CALL(*storage, get_value(_, _)).Times(0);
  EXPECT_CALL(*storage, set_value(_, _)).Times(0);
  EXPECT_CALL(*storage, set_value("PeriodicUpdateCheckEnabled", SettingValue{true}))
    .Times(1)
    .WillOnce(Return(outcome::success()));
  EXPECT_CALL(*storage, set_value("PeriodicUpdateCheckEnabled", SettingValue{false}))
    .Times(1)
    .WillOnce(Return(outcome::failure(UnfoldInternalErrc::InvalidSetting)));

  Settings settings(storage);
  settings.set_periodic_update_check_enabled(true);
  settings.set_periodic_update_check_enabled(false);
}

TEST(SettingsTest,  GetSkipVerion)
{
  auto storage = std::make_shared<SettingsStorageMock>();

  EXPECT_CALL(*storage, set_prefix(_)).Times(0);
  EXPECT_CALL(*storage, remove_key(_)).Times(0);
  EXPECT_CALL(*storage, set_value(_, _)).Times(0);
  EXPECT_CALL(*storage, get_value("SkipVersion", SettingType::String))
    .Times(2)
    .WillOnce(Return(outcome::success("1.10.56")))
    .WillOnce(Return(outcome::failure(UnfoldInternalErrc::InvalidSetting)));

  Settings settings(storage);
  auto rc = settings.get_skip_version();
  EXPECT_EQ(rc, "1.10.56");
  rc = settings.get_skip_version();
  EXPECT_EQ(rc, "");
}

TEST(SettingsTest,  SetSkipVerion)
{
  auto storage = std::make_shared<SettingsStorageMock>();

  EXPECT_CALL(*storage, set_prefix(_)).Times(0);
  EXPECT_CALL(*storage, remove_key(_)).Times(0);
  EXPECT_CALL(*storage, get_value(_, _)).Times(0);
  EXPECT_CALL(*storage, set_value("SkipVersion", SettingValue{"1.10.75"})).Times(1).WillOnce(Return(outcome::success()));
  EXPECT_CALL(*storage, set_value("SkipVersion", SettingValue{"2.30.75"}))
    .Times(1)
    .WillOnce(Return(outcome::failure(UnfoldInternalErrc::InvalidSetting)));

  Settings settings(storage);
  settings.set_skip_version("1.10.75");
  settings.set_skip_version("2.30.75");
}

TEST(SettingsTest,  GetPriority)
{
  auto storage = std::make_shared<SettingsStorageMock>();

  EXPECT_CALL(*storage, set_prefix(_)).Times(0);
  EXPECT_CALL(*storage, remove_key(_)).Times(0);
  EXPECT_CALL(*storage, set_value(_, _)).Times(0);
  EXPECT_CALL(*storage, get_value("Priority", SettingType::Int32)).Times(1).WillOnce(Return(outcome::success(10)));

  Settings settings(storage);
  auto rc = settings.get_priority();
  EXPECT_EQ(rc, 10);
}

TEST(SettingsTest,  SetPriority)
{
  auto storage = std::make_shared<SettingsStorageMock>();

  EXPECT_CALL(*storage, set_prefix(_)).Times(0);
  EXPECT_CALL(*storage, remove_key(_)).Times(0);
  EXPECT_CALL(*storage, get_value(_, _)).Times(0);
  EXPECT_CALL(*storage, set_value("Priority", SettingValue{10})).Times(1).WillOnce(Return(outcome::success()));
  EXPECT_CALL(*storage, set_value("Priority", SettingValue{101}))
    .Times(1)
    .WillOnce(Return(outcome::failure(UnfoldInternalErrc::InvalidSetting)));

  Settings settings(storage);
  settings.set_priority(10);
  settings.set_priority(101);
}

namespace
{
  template<class T>
  std::string to_string(const T &x)
  {
    std::ostringstream ss;
    ss << x;
    return ss.str();
  }
} // namespace

TEST(SettingsTest,  Value)
{
  SettingValue i64{478LL};
  EXPECT_EQ(to_string(i64), "478");
  EXPECT_EQ(to_string(SettingValueToType(i64)), "Int64");
  SettingValue i32{41248};
  EXPECT_EQ(to_string(i32), "41248");
  EXPECT_EQ(to_string(SettingValueToType(i32)), "Int32");
  SettingValue b{true};
  EXPECT_EQ(to_string(b), "1");
  EXPECT_EQ(to_string(SettingValueToType(b)), "Boolean");
  SettingValue s{"foo"};
  EXPECT_EQ(to_string(s), "foo");
  EXPECT_EQ(to_string(SettingValueToType(s)), "String");
}
