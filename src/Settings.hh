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

#ifndef SETTINGS_HH
#define SETTINGS_HH

#include <memory>
#include <optional>

#include "utils/Logging.hh"
#include "SettingsStorage.hh"

class Settings
{
public:
  explicit Settings(std::shared_ptr<SettingsStorage> storage);

  std::optional<std::chrono::system_clock::time_point> get_last_update_check_time() const;
  void set_last_update_check_time(std::chrono::system_clock::time_point);

  std::string get_skip_version() const;
  void set_skip_version(std::string version);

  std::chrono::seconds get_periodic_update_check_interval() const;
  void set_periodic_update_check_interval(std::chrono::seconds interval);

  bool get_periodic_update_check_enabled() const;
  void set_periodic_update_check_enabled(bool enabled);

  int get_priority() const;
  void set_priority(int priority);

private:
  std::shared_ptr<SettingsStorage> storage;
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:settings")};
};

#endif // SETTINGS_HH
