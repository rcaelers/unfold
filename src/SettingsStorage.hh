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

#ifndef SETTINGS_STORAGE_HH
#define SETTINGS_STORAGE_HH

#include <memory>
#include <string>
#include <variant>
#include <optional>

enum class SettingType
{
  Unknown,
  Boolean,
  Int32,
  Int64,
  Double,
  String,
};

using SettingValue = std::variant<bool, int32_t, int64_t, double, std::string>;

constexpr SettingType
SettingValueToType(SettingValue &value)
{
  return std::visit(
    [](auto &&arg) {
      using T = std::decay_t<decltype(arg)>;

      if constexpr (std::is_same_v<bool, T>)
        {
          return SettingType::Boolean;
        }
      else if constexpr (std::is_same_v<int64_t, T>)
        {
          return SettingType::Int64;
        }
      else if constexpr (std::is_same_v<int32_t, T>)
        {
          return SettingType::Int32;
        }
      else if constexpr (std::is_same_v<double, T>)
        {
          return SettingType::Double;
        }
      else if constexpr (std::is_same_v<std::string, T>)
        {
          return SettingType::String;
        }
    },
    value);
}

inline std::ostream &
operator<<(std::ostream &os, const SettingValue &value)
{
  std::visit([&os](auto &&arg) { os << arg; }, value);
  return os;
}

class SettingsStorage
{
public:
  virtual ~SettingsStorage() = default;

  static std::shared_ptr<SettingsStorage> create();

  virtual void set_prefix(const std::string &prefix) = 0;

  virtual void remove_key(const std::string &name) = 0;
  virtual std::optional<SettingValue> get_value(const std::string &name, SettingType type) const = 0;
  virtual void set_value(const std::string &name, const SettingValue &value) = 0;
};

#endif // SETTINGS_STORAGE_HH
