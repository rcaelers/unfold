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

#ifndef WINDOWS_SETTINGS_STORAGE_HH
#define WINDOWS_SETTINGS_STORAGE_HH

#include "SettingsStorage.hh"

#include <string>

#include "utils/Logging.hh"

class WindowsSettingsStorage : public SettingsStorage
{
public:
  ~WindowsSettingsStorage() override = default;

  outcome::std_result<void> set_prefix(const std::string &prefix) override;
  outcome::std_result<void> remove_key(const std::string &name) override;
  outcome::std_result<SettingValue> get_value(const std::string &name, SettingType type) const override;
  outcome::std_result<void> set_value(const std::string &name, const SettingValue &value) override;

private:
  std::string subkey_;
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:windows")};
};

#endif // WINDOWS_SETTINGS_STORAGE_HH
