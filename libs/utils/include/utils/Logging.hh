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

#ifndef UTILS_LOGGING_HH
#define UTILS_LOGGING_HH

#include <string>
#include <sstream>
#include <spdlog/spdlog.h>
#include <fmt/core.h>
#include <fmt/format.h>
#include <boost/system/error_code.hpp>
#include <boost/core/detail/string_view.hpp>

namespace unfold::utils
{
  class Logging
  {
  public:
    static std::shared_ptr<spdlog::logger> create(std::string domain);
  };
} // namespace unfold::utils

template<>
struct fmt::formatter<boost::system::error_code> : fmt::formatter<std::string>
{
  auto format(boost::system::error_code e, format_context &ctx) const
  {
    std::ostringstream ss;
    ss << e;
    auto s = ss.str();
    return fmt::formatter<std::string>::format(s, ctx);
  }
};

template<typename C>
struct fmt::formatter<boost::core::basic_string_view<C>> : fmt::formatter<std::string_view>
{
  auto format(const typename boost::core::basic_string_view<C> &s, format_context &ctx) const
  {
    return fmt::formatter<std::string_view>::format((std::string_view(s)), ctx);
  }
};

#endif // UTILS_WORKAVE_LIBS_UTILS_LOGGING_HH
