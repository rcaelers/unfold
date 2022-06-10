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

#include "Settings.hh"

#include <chrono>
#include <optional>
#include <utility>

#include <spdlog/fmt/ostr.h>

namespace
{
  constexpr const char *last_update_check_time = "LastUpdateCheckTime";
  constexpr const char *skip_version = "SkipVersion";
  constexpr const char *periodic_update_check_interval = "PeriodicUpdateCheckInterval";
  constexpr const char *periodic_update_check_enabled = "PeriodicUpdateCheckEnabled";
} // namespace

Settings::Settings(std::shared_ptr<SettingsStorage> storage)
  : storage(std::move(storage))
{
}

std::optional<std::chrono::system_clock::time_point>
Settings::get_last_update_check_time() const
{
  auto l = storage->get_value(last_update_check_time, SettingType::Int64);
  if (l)
    {
      return std::chrono::system_clock::time_point(std::chrono::seconds(std::get<int64_t>(l.value())));
    }
  return {};
}

void
Settings::set_last_update_check_time(std::chrono::system_clock::time_point t)
{
  auto rc = storage->set_value(last_update_check_time, static_cast<int64_t>(t.time_since_epoch().count()));
  if (!rc)
    {
      spdlog::error("Failed to set last update check time");
    }
}

std::string
Settings::get_skip_version() const
{
  auto version = storage->get_value(skip_version, SettingType::String);
  if (version)
    {
      return std::get<std::string>(version.value());
    }
  return {};
}

void
Settings::set_skip_version(std::string version)
{
  auto rc = storage->set_value(skip_version, version);
  if (!rc)
    {
      spdlog::error("Failed to set skip version");
    }
}

std::chrono::seconds
Settings::get_periodic_update_check_interval() const
{
  auto interval = storage->get_value(periodic_update_check_interval, SettingType::Int64);
  if (interval)
    {
      return std::chrono::seconds(std::get<int64_t>(interval.value()));
    }
  return {};
}

void
Settings::set_periodic_update_check_interval(std::chrono::seconds interval)
{
  auto rc = storage->set_value(periodic_update_check_interval, static_cast<int64_t>(interval.count()));
  if (!rc)
    {
      spdlog::error("Failed to set periodic update interval");
    }
}

bool
Settings::get_periodic_update_check_enabled() const
{
  auto enabled = storage->get_value(periodic_update_check_enabled, SettingType::Boolean);
  if (enabled)
    {
      return std::get<bool>(enabled.value());
    }
  return {};
}

void
Settings::set_periodic_update_check_enabled(bool enabled)
{
  auto rc = storage->set_value(periodic_update_check_enabled, enabled);
  if (!rc)
    {
      spdlog::error("Failed to set periodic update check enabled");
    }
}
