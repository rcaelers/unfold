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

#ifndef WORKAVE_LIBS_UTILS_ENUM_ITERATOR_HH
#define WORKAVE_LIBS_UTILS_ENUM_ITERATOR_HH

#include "Enum.hh"

#include <boost/iterator/iterator_categories.hpp>
#include <boost/iterator/iterator_facade.hpp>
#include <boost/range/iterator_range.hpp>

#include <iostream>

namespace unfold::utils
{
  template<typename Enum>
  class enum_iterator : public boost::iterator_facade<enum_iterator<Enum>, Enum, boost::random_access_traversal_tag, Enum>
  {
    static_assert(enum_has_min_v<Enum> && enum_has_max_v<Enum>, "Enum must have enum_traits with min and max");

  public:
    constexpr enum_iterator()
      : index{enum_max_value<Enum>() + 1}
    {
    }

    constexpr explicit enum_iterator(std::underlying_type_t<Enum> value)
      : index{value}
    {
    }

  private:
    void advance(std::ptrdiff_t n)
    {
      index += n;
    }

    void decrement()
    {
      --index;
    }

    void increment()
    {
      ++index;
    }

    std::ptrdiff_t distance_to(const enum_iterator &other) const
    {
      return other.index - index;
    }

    bool equal(const enum_iterator &other) const
    {
      return other.index == index;
    }

    Enum dereference() const
    {
      return static_cast<Enum>(index);
    }

    friend class boost::iterator_core_access;

  private:
    std::underlying_type_t<Enum> index;
  };

  template<typename Enum>
  class enum_value_iterator
    : public boost::iterator_facade<enum_value_iterator<Enum>,
                                    std::underlying_type_t<Enum>,
                                    boost::random_access_traversal_tag,
                                    const std::underlying_type_t<Enum> &>
  {
    static_assert(enum_has_min_v<Enum> && enum_has_max_v<Enum>, "Enum must have enum_traits with min and max");

  public:
    constexpr enum_value_iterator()
      : index{enum_max_value<Enum>() + 1}
    {
    }

    constexpr explicit enum_value_iterator(std::underlying_type_t<Enum> value)
      : index{value}
    {
    }

  private:
    void advance(std::ptrdiff_t n)
    {
      index += n;
    }

    void decrement()
    {
      --index;
    }

    void increment()
    {
      ++index;
    }

    std::ptrdiff_t distance_to(const enum_value_iterator &other) const
    {
      return other.index - index;
    }

    bool equal(const enum_value_iterator &other) const
    {
      return other.index == index;
    }

    const std::underlying_type_t<Enum> &dereference() const
    {
      return index;
    }

    friend class boost::iterator_core_access;

  private:
    std::underlying_type_t<Enum> index;
  };

  template<typename Enum>
  constexpr auto enum_range() noexcept
  {
    return boost::make_iterator_range(enum_iterator<Enum>{enum_min_value<Enum>()},
                                      enum_iterator<Enum>{enum_max_value<Enum>() + 1});
  }

  template<typename Enum>
  constexpr auto enum_value_range() noexcept
  {
    return boost::make_iterator_range(enum_value_iterator<Enum>{enum_min_value<Enum>()},
                                      enum_value_iterator<Enum>{enum_max_value<Enum>() + 1});
  }
} // namespace unfold::utils

#endif // WORKAVE_LIBS_UTILS_ENUM_ITERATOR_HH
