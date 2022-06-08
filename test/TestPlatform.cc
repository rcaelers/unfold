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

#include "TestPlatform.hh"

#include <boost/algorithm/string.hpp>

#include "semver.hpp"

bool
TestPlatform::is_supported_os(const std::string &os)
{
  if (boost::iequals(os, "windows"))
    {
      return true;
    }
  if (boost::iequals(os, "windows-x64"))
    {
      return true;
    }
  return false;
}

bool
TestPlatform::is_supported_os_version(const std::string &minimum_version)
{
  if (minimum_version.empty())
    {
      return true;
    }
  semver::version version;
  bool version_ok = version.from_string_noexcept(minimum_version);
  if (!version_ok)
    {
      return false;
    }
  semver::version current_version;
  current_version.from_string("10.10.10");
  return version >= current_version;
}

void
TestPlatform::terminate()
{
  terminated = true;
}

bool
TestPlatform::is_terminated() const
{
  return terminated;
}
