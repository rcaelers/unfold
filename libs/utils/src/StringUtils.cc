// Copyright (C) 2021, 2022 Rob Caelers <rob.caelers@gmail.com>
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

#include "utils/StringUtils.hh"

#include <windows.h>

std::string
unfold::utils::utf16_to_utf8(const std::wstring &s)
{
  std::string ret;
  int len = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), s.length(), nullptr, 0, nullptr, nullptr);
  if (len > 0)
    {
      ret.resize(len);
      WideCharToMultiByte(CP_UTF8, 0, s.c_str(), s.length(), ret.data(), len, nullptr, nullptr);
    }
  return ret;
}

std::wstring
unfold::utils::utf8_to_utf16(const std::string &s)
{
  std::wstring ret;
  int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), s.length(), nullptr, 0);
  if (len > 0)
    {
      ret.resize(len);
      MultiByteToWideChar(CP_UTF8, 0, s.c_str(), s.length(), ret.data(), len);
    }
  return ret;
}
