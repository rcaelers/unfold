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

#include "WindowsSettingsStorage.hh"

#include <memory>
#include <string>
#include "boost/lexical_cast.hpp"

#include <variant>
#include <windows.h>

std::shared_ptr<SettingsStorage>
SettingsStorage::create()
{
  return std::make_shared<WindowsSettingsStorage>();
}

void
WindowsSettingsStorage::set_prefix(const std::string &prefix)
{
  subkey_ = prefix;
}

void
WindowsSettingsStorage::remove_key(const std::string &name)
{
  HKEY key = nullptr;
  LONG err = RegOpenKeyEx(HKEY_CURRENT_USER, subkey_.c_str(), 0, KEY_ALL_ACCESS, &key);
  if (err == ERROR_SUCCESS)
    {
      err = RegDeleteValueA(key, name.c_str());
      if (err != ERROR_SUCCESS)
        {
          logger->error("failed to delete registry key {}\\{}", subkey_, name);
        }
      RegCloseKey(key);
    }
}

std::optional<SettingValue>
WindowsSettingsStorage::get_value(const std::string &name, SettingType type) const
{
  HKEY key = nullptr;

  LONG err = RegOpenKeyEx(HKEY_CURRENT_USER, subkey_.c_str(), 0, KEY_ALL_ACCESS, &key);
  if (err != ERROR_SUCCESS)
    {
      logger->error("failed to open registry key {}\\{}", subkey_, name);
      return {};
    }

  std::string value;

  DWORD size = 0;
  err = RegQueryValueExA(key, name.c_str(), nullptr, nullptr, nullptr, &size);

  if (err != ERROR_SUCCESS || (size == 0))
    {
      logger->error("failed to read registry key {}\\{}", subkey_, name);
      RegCloseKey(key);
      return {};
    }

  DWORD regtype = 0;
  std::vector<char> data(size + 1);

  err = RegQueryValueExA(key, name.c_str(), nullptr, &regtype, (LPBYTE)data.data(), &size);
  if (err != ERROR_SUCCESS || regtype != REG_SZ)
    {
      logger->error("failed to read registry key {}\\{}", subkey_, name);
      RegCloseKey(key);
      return {};
    }

  data[size] = '\0';
  value = data.data();

  RegCloseKey(key);
  switch (type)
    {
    case SettingType::Int32:
      return boost::lexical_cast<int32_t>(value);

    case SettingType::Int64:
      return boost::lexical_cast<int64_t>(value);

    case SettingType::Boolean:
      return boost::lexical_cast<bool>(value);

    case SettingType::Double:
      return boost::lexical_cast<double>(value);

    case SettingType::Unknown:
      [[fallthrough]];

    case SettingType::String:
      return value;
    }
  return {};
}

void
WindowsSettingsStorage::set_value(const std::string &name, const SettingValue &value)
{
  std::visit(
    [this, name](auto &&arg) {
      using T = std::decay_t<decltype(arg)>;

      std::string v;

      if constexpr (std::is_same_v<std::string, T>)
        {
          v = arg;
        }
      else if constexpr (!std::is_same_v<std::monostate, T>)
        {
          v = std::to_string(arg);
        }

      HKEY key = nullptr;
      DWORD disp = 0;
      LONG err = RegCreateKeyEx(HKEY_CURRENT_USER,
                                subkey_.c_str(),
                                0,
                                nullptr,
                                REG_OPTION_NON_VOLATILE,
                                KEY_ALL_ACCESS,
                                nullptr,
                                &key,
                                &disp);
      if (err != ERROR_SUCCESS)
        {
          logger->error("failed to read registry key {}\\{}", subkey_, name);
          RegCloseKey(key);
          return;
        }

      err = RegSetValueEx(key, name.c_str(), 0, REG_SZ, (BYTE *)v.c_str(), static_cast<DWORD>(v.length() + 1));
      RegCloseKey(key);
      if (err != ERROR_SUCCESS)
        {
          logger->error("failed to set registry key {}\\{}", subkey_, name);
          return;
        }
    },
    value);
}
