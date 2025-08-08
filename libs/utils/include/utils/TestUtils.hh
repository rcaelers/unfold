// Copyright (C) 2025 Rob Caelers <rob.caelers@gmail.com>
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

#pragma once

#include <string>
#include <filesystem>

inline std::string
find_test_data_file(const std::string &filename)
{
#ifdef TEST_DATA_DIR
  std::string test_data_dir = TEST_DATA_DIR;
  std::filesystem::path test_data_path = std::filesystem::path(test_data_dir) / filename;
#else
  std::filesystem::path test_data_path = std::filesystem::current_path() / filename;
#endif
  return test_data_path.string();
}

inline std::string
find_test_bin_file(const std::string &filename)
{
#ifdef TEST_BIN_DIR
  std::string test_bin_dir = TEST_BIN_DIR;
  std::filesystem::path test_bin_path = std::filesystem::path(test_bin_dir) / filename;
#else
  std::filesystem::path test_bin_path = std::filesystem::current_path() / filename;
#endif
  return test_bin_path.string();
}
