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

#include "DummySettingsStorage.hh"

#include <memory>
#include <string>
#include "boost/lexical_cast.hpp"

void
DummySettingsStorage::set_prefix(const std::string &prefix)
{
}

void
DummySettingsStorage::remove_key(const std::string &name)
{
  store.erase(name);
}

std::optional<SettingValue>
DummySettingsStorage::get_value(const std::string &name, SettingType type) const
{
  if (!store.contains(name))
    {
      return {};
    }

  auto value = store.at(name);

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
DummySettingsStorage::set_value(const std::string &name, const SettingValue &value)
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

      store[name] = v;
    },
    value);
}
