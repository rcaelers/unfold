// Copyright (C) 2024 Rob Caelers <rob.caelers@gmail.com>
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

#include "utils/DateUtils.hh"

#include <boost/date_time/gregorian/gregorian.hpp>
#include <chrono>
#include <sstream>

using namespace unfold::utils;

std::optional<boost::posix_time::ptime>
DateUtils::try_parse(const std::string &date_str, const std::string &format)
{
  std::locale locale(std::locale::classic(), new boost::posix_time::time_input_facet(format));
  std::istringstream iss(date_str);
  iss.imbue(locale);

  boost::posix_time::ptime pt;
  iss >> pt;

  if (pt != boost::posix_time::ptime())
    {
      return pt;
    }
  return std::nullopt;
}

std::chrono::system_clock::time_point
DateUtils::parse_time_point(const std::string &date_str)
{
  const std::vector<std::string> formats = {
    "%a, %d %b %Y %H:%M:%S %ZP", // RFC 1123/2822
    "%Y-%m-%dT%H:%M:%SZ",        // ISO 8601 UTC
    "%Y-%m-%dT%H:%M:%S"          // ISO 8601 without 'Z'
  };

  boost::posix_time::ptime pt;
  for (const auto &format: formats)
    {
      if (auto parsed_pt = try_parse(date_str, format); parsed_pt.has_value())
        {
          pt = parsed_pt.value();
          break;
        }
    }

  if (pt == boost::posix_time::ptime())
    {
      throw std::runtime_error("Failed to parse time string");
    }

  boost::posix_time::ptime epoch(boost::gregorian::date(1970, 1, 1));
  boost::posix_time::time_duration duration = pt - epoch;
  return std::chrono::system_clock::time_point(std::chrono::seconds(duration.total_seconds()));
}
