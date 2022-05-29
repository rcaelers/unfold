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

#include "utils/TempDirectory.hh"

#include <array>
#include <random>
#include <algorithm>

#include <spdlog/spdlog.h>

using namespace unfold::utils;

TempDirectory::TempDirectory()
{
  std::filesystem::path temp_path = std::filesystem::temp_directory_path();

  int tries = 0;
  while (true)
    {
      path = temp_path / generate_random_string(random_string_length);

      if (!std::filesystem::exists(path))
        {
          break;
        }

      if (tries >= max_tries)
        {
          throw std::runtime_error("failed to create unique temp directory");
        }

      tries++;
    }

  spdlog::info("create temp directory {}", path.string());
  std::filesystem::create_directories(path);
}

TempDirectory::~TempDirectory()
{
  // TODO: std::filesystem::remove_all(path);
}

std::filesystem::path
TempDirectory::get_path() const
{
  return path;
}

std::string
TempDirectory::generate_random_string(std::size_t len)
{
  static constexpr auto charset = std::to_array(
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz");
  const size_t max_index = (sizeof(charset) - 1);

  std::random_device rnd;
  std::mt19937 generator(rnd());
  std::uniform_int_distribution<> distribution(0, max_index);

  auto randchar = [&distribution, &generator]() -> char { return charset[distribution(generator)]; };

  auto result = std::string(len, '\0');
  std::generate_n(begin(result), len, randchar);
  return result;
}
