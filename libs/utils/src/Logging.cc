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

#include "utils/Logging.hh"

#include <spdlog/spdlog.h>

#ifdef _WIN32
#  include <windows.h>
#  include <io.h>
#  include <fcntl.h>
#endif

using namespace unfold::utils;

std::shared_ptr<spdlog::logger>
Logging::create(std::string domain)
{
#ifdef _WIN32
  // Set console to UTF-8 for proper Unicode display (only do this once)
  static bool utf8_initialized = false;
  if (!utf8_initialized)
    {
      // Set console code page to UTF-8
      SetConsoleOutputCP(CP_UTF8);
      SetConsoleCP(CP_UTF8);

      // Enable UTF-8 for stdout/stderr
      _setmode(_fileno(stdout), _O_U8TEXT);
      _setmode(_fileno(stderr), _O_U8TEXT);

      utf8_initialized = true;
    }
#endif

  return spdlog::default_logger()->clone(domain);
}
