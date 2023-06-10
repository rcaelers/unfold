// Copyright (C) 2021 Rob Caelers <rob.caelers@gmail.com>
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

#ifndef WORKAVE_LIBS_UTILS_ENUM_HH
#define WORKAVE_LIBS_UTILS_ENUM_HH

#include <type_traits>
#include <utility>
#include <array>
#include <algorithm>

#include <iostream>
#include <sstream>

#include <fmt/core.h>
#include <fmt/format.h>

namespace unfold::utils
{
  template<typename Enum>
  using is_scoped_enum = std::conjunction<std::is_enum<Enum>,
                                          std::negation<std::is_convertible<Enum, std::underlying_type_t<Enum>>>>;

  template<typename Enum>
  static constexpr bool is_scoped_enum_v = is_scoped_enum<Enum>::value;

  template<typename Enum>
  constexpr auto underlying_cast(Enum e) noexcept
  {
    return static_cast<std::underlying_type_t<Enum>>(e);
  }

  template<typename Enum>
  struct enum_traits
  {
  };

  template<typename Enum, typename = std::void_t<>>
  struct enum_has_min : std::false_type
  {
  };

  template<typename Enum>
  struct enum_has_min<Enum, std::void_t<decltype(enum_traits<Enum>::min)>> : std::true_type
  {
  };

  template<typename Enum>
  constexpr inline bool enum_has_min_v = enum_has_min<Enum>::value;

  template<typename Enum, typename = std::void_t<>>
  struct enum_has_max : std::false_type
  {
  };

  template<typename Enum>
  struct enum_has_max<Enum, std::void_t<decltype(enum_traits<Enum>::max)>> : std::true_type
  {
  };

  template<typename Enum>
  constexpr inline bool enum_has_max_v = enum_has_max<Enum>::value;

  template<typename Enum, typename = std::void_t<>>
  struct enum_has_names : std::false_type
  {
  };

  template<typename Enum>
  struct enum_has_names<Enum, std::void_t<decltype(enum_traits<Enum>::names)>> : std::true_type
  {
  };

  template<typename Enum>
  constexpr inline bool enum_has_names_v = enum_has_names<Enum>::value;

  template<typename Enum, typename = std::void_t<>>
  struct enum_has_invalid : std::false_type
  {
  };

  template<typename Enum>
  struct enum_has_invalid<Enum, std::void_t<decltype(enum_traits<Enum>::invalid)>> : std::true_type
  {
  };

  template<typename Enum>
  constexpr inline bool enum_has_invalid_v = enum_has_invalid<Enum>::value;

  template<typename Enum, std::enable_if_t<enum_has_min_v<Enum>, int> = 0>
  constexpr auto enum_min_value() noexcept
  {
    return underlying_cast(enum_traits<Enum>::min);
  }

  template<typename Enum, std::enable_if_t<enum_has_max_v<Enum>, int> = 0>
  constexpr auto enum_max_value() noexcept
  {
    return underlying_cast(enum_traits<Enum>::max);
  }

  template<typename Enum, std::enable_if_t<enum_has_max_v<Enum> && enum_has_min_v<Enum>, int> = 0>
  constexpr auto enum_count() noexcept
  {
    return enum_max_value<Enum>() - enum_min_value<Enum>() + 1;
  }

  template<typename Enum, std::enable_if_t<enum_has_max_v<Enum> && enum_has_min_v<Enum>, int> = 0>
  constexpr auto enum_in_range(std::underlying_type_t<Enum> v) noexcept
  {
    return (v >= enum_min_value<Enum>()) && (v <= enum_max_value<Enum>());
  }

  template<typename Enum, std::enable_if_t<enum_has_max_v<Enum> && enum_has_min_v<Enum>, int> = 0>
  constexpr auto enum_in_range(Enum e) noexcept
  {
    return (underlying_cast(e) >= enum_min_value<Enum>()) && (underlying_cast(e) <= enum_max_value<Enum>());
  }

  template<typename Enum>
  Enum enum_from_string(std::string key)
  {
    auto &names = enum_traits<Enum>::names;
    const auto it = std::find_if(begin(names), end(names), [&key](const auto &v) { return v.first == key; });
    if (it == std::end(names))
      {
        if constexpr (enum_has_invalid_v<Enum>)
          {
            return enum_traits<Enum>::invalid;
          }
        if constexpr (enum_has_min_v<Enum>)
          {
            return enum_traits<Enum>::min;
          }
      }
    return it->second;
  }

  template<typename Enum>
  std::string_view enum_to_string(Enum e)
  {
    auto &names = enum_traits<Enum>::names;
    const auto it = std::find_if(begin(names), end(names), [&e](const auto &v) { return v.second == e; });
    if (it == std::end(names))
      {
        return {};
      }
    return it->first;
  }

  template<typename Enum, class T, std::size_t N = unfold::utils::enum_count<Enum>()>
  class array : public std::array<T, N>
  {
  public:
    using base = std::array<T, N>;

    constexpr array()
      : base{}
    {
    }

    template<class... Args>
    constexpr array(Args &&...args)
      : base{{std::forward<Args>(args)...}}
    {
    }

    using base::operator[];

    constexpr T &operator[](Enum e)
    {
      return base::operator[](underlying_cast(e) - unfold::utils::enum_min_value<Enum>());
    }

    constexpr const T &operator[](Enum e) const
    {
      return base::operator[](underlying_cast(e) - unfold::utils::enum_min_value<Enum>());
    }
  };

  template<typename Enum>
  requires unfold::utils::enum_traits<Enum>::flag
  class Flags
  {
  public:
    using underlying_type = typename std::underlying_type_t<Enum>;
    using repr_type = typename std::make_unsigned_t<underlying_type>;

    Flags() noexcept = default;
    Flags(const Flags &) noexcept = default;
    Flags(Flags &&) noexcept = default;
    Flags &operator=(const Flags &) noexcept = default;
    Flags &operator=(Flags &&) noexcept = default;

    constexpr Flags(Enum e) noexcept
      : value{static_cast<repr_type>(e)}
    {
    }

    constexpr Flags &operator=(Enum e) noexcept
    {
      value = static_cast<repr_type>(e);
      return *this;
    }

    constexpr underlying_type get() const noexcept
    {
      return static_cast<underlying_type>(value);
    }

    constexpr void set(underlying_type val) noexcept
    {
      value = static_cast<repr_type>(val);
    }

    constexpr bool is_set(Enum e) const noexcept
    {
      return (value & static_cast<repr_type>(e)) == static_cast<repr_type>(e);
    }

    constexpr bool is_set(Flags other) const noexcept
    {
      return (value & other.value) == other.value;
    }

    constexpr void clear() noexcept
    {
      value = 0;
    }

    constexpr bool operator==(Flags other) const noexcept
    {
      return value == other.value;
    }

    constexpr bool operator!=(Flags other) const noexcept
    {
      return value != other.value;
    }

    constexpr Flags operator&(Flags other) const noexcept
    {
      return Flags{value & other.value};
    }

    constexpr Flags operator|(Flags other) const noexcept
    {
      return Flags{value | other.value};
    }

    constexpr Flags operator^(Flags other) const noexcept
    {
      return Flags{value ^ other.value};
    };

    constexpr Flags &operator&=(const Flags &other) noexcept
    {
      value &= other.value;
      return *this;
    }

    constexpr Flags &operator|=(const Flags &other) noexcept
    {
      value |= other.value;
      return *this;
    }

    constexpr Flags &operator^=(const Flags &other) noexcept
    {
      value ^= other.value;
      return *this;
    }

    constexpr Flags &operator&=(Enum e) noexcept
    {
      value &= static_cast<repr_type>(e);
      return *this;
    }

    constexpr Flags &operator|=(Enum e) noexcept
    {
      value |= static_cast<repr_type>(e);
      return *this;
    }

    constexpr Flags &operator^=(Enum e) noexcept
    {
      value ^= static_cast<repr_type>(e);
      return *this;
    }

    constexpr Flags operator~() const noexcept
    {
      return Flags{~value};
    }

    constexpr explicit operator bool() const noexcept
    {
      return value != 0;
    }

  private:
    constexpr explicit Flags(repr_type val)
      : value{val}
    {
    }

    repr_type value{0};
  };

  template<typename Enum>
  requires ::unfold::utils::enum_traits<Enum>::flag
  std::ostream &operator<<(std::ostream &stream, ::unfold::utils::Flags<Enum> flags)
  {
    if (flags.get() == 0)
      {
        stream << unfold::utils::enum_to_string(Enum(0));
      }
    else
      {
        for (int b = 0; b < unfold::utils::enum_traits<Enum>::bits; b++)
          {
            Enum e = static_cast<Enum>(1 << b);
            if (flags.is_set(e))
              {
                if (b > 0)
                  {
                    stream << ",";
                  }
                stream << unfold::utils::enum_to_string(e);
              }
          }
      }
    return stream;
  }
} // namespace unfold::utils

template<typename Enum>
requires unfold::utils::enum_has_names_v<Enum>
std::ostream &
operator<<(std::ostream &stream, const Enum e)
{
  stream << unfold::utils::enum_to_string(e);
  return stream;
}

template<typename Enum, typename = std::enable_if_t<unfold::utils::enum_traits<Enum>::linear>>
constexpr Enum
operator++(Enum &e) noexcept
{
  e = static_cast<Enum>(unfold::utils::underlying_cast(e) + 1);
  return e;
}

template<typename Enum, typename = std::enable_if_t<unfold::utils::enum_traits<Enum>::linear>>
constexpr Enum
operator++(Enum &e, int) noexcept
{
  const auto ret = e;
  e = static_cast<Enum>(unfold::utils::underlying_cast(e) + 1);
  return ret;
}

template<typename Enum, typename = std::enable_if_t<unfold::utils::enum_traits<Enum>::flag>>
constexpr auto
operator|(Enum lhs, Enum rhs) noexcept
{
  return unfold::utils::Flags<Enum>(lhs) | rhs;
}

template<typename Enum, typename = std::enable_if_t<unfold::utils::enum_traits<Enum>::flag>>
constexpr auto
operator&(Enum lhs, Enum rhs) noexcept
{
  return unfold::utils::Flags<Enum>(lhs) & rhs;
}

template<typename Enum, typename = std::enable_if_t<unfold::utils::enum_traits<Enum>::flag>>
constexpr auto
operator^(Enum lhs, Enum rhs) noexcept
{
  return unfold::utils::Flags<Enum>(lhs) ^ rhs;
}

template<typename Enum, typename = std::enable_if_t<unfold::utils::enum_traits<Enum>::flag>>
constexpr auto
operator~(Enum e) noexcept
{
  return ~unfold::utils::Flags<Enum>(e);
}

template<typename Enum>
requires unfold::utils::enum_has_names_v<Enum>
struct fmt::formatter<Enum> : fmt::formatter<std::string_view>
{
  auto format(Enum e, format_context &ctx) const
  {
    return fmt::formatter<std::string_view>::format(unfold::utils::enum_to_string<Enum>(e), ctx);
  }
};

template<typename Enum>
requires unfold::utils::enum_has_names_v<Enum>
struct fmt::formatter<unfold::utils::Flags<Enum>> : fmt::formatter<std::string>
{
  auto format(typename unfold::utils::Flags<Enum> e, format_context &ctx) const
  {
    std::ostringstream ss;
    ss << e;
    auto s = ss.str();
    return fmt::formatter<std::string>::format(s, ctx);
  }
};

#endif // WORKAVE_LIBS_UTILS_ENUM_HH
