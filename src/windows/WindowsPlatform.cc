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

#include "WindowsPlatform.hh"

#include <windows.h>

#include <boost/algorithm/string.hpp>

#include "semver.hpp"

bool
WindowsPlatform::is_supported_os(const std::string &os)
{
  if (boost::iequals(os, "windows"))
    {
      return true;
    }
#ifdef _WIN64
  if (boost::iequals(os, "windows-x64"))
    {
      return true;
    }
#else
  if (boost::iequals(os, "windows-x86"))
    {
      return true;
    }
#endif
  return false;
}

bool
WindowsPlatform::is_supported_os_version(const std::string &minimum_version)
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

  OSVERSIONINFOEXW osvi = {sizeof(osvi), version.major, version.minor, version.patch, 0, {0}, 0, 0};

  return !VerifyVersionInfoW(&osvi,
                             VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR,
                             VerSetConditionMask(VerSetConditionMask(VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL),
                                                                     VER_MINORVERSION,
                                                                     VER_GREATER_EQUAL),
                                                 VER_SERVICEPACKMAJOR,
                                                 VER_GREATER_EQUAL));
}
