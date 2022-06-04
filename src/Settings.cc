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

#include <spdlog/fmt/ostr.h>

namespace
{
  constexpr const char *last_update_check_time = "LastUpdateCheckTime";
  constexpr const char *skip_version = "SkipVersion";
  constexpr const char *periodic_update_check = "PeriodicUpdateCheck";
} // namespace

Settings::Settings(std::shared_ptr<SettingsStorage> storage)
  : storage(storage)
{
}

std::optional<std::chrono::system_clock::time_point>
Settings::get_last_update_check_time()
{
  auto l = storage->get_value(last_update_check_time, SettingType::Int64);
  if (l)
    {
      return std::chrono::system_clock::time_point(std::chrono::seconds(std::get<int64_t>(*l)));
    }
  return {};
}

void
Settings::set_last_update_check_time(std::chrono::system_clock::time_point t)
{
  storage->set_value(last_update_check_time, static_cast<int64_t>(t.time_since_epoch().count()));
}

std::string
Settings::get_skip_version()
{
  auto version = storage->get_value(skip_version, SettingType::String);
  if (version)
    {
      return std::get<std::string>(*version);
    }
  return {};
}

void
Settings::set_skip_version(std::string version)
{
  storage->set_value(skip_version, version);
}
