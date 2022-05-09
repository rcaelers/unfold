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

#ifndef UTILS_TEMPDIRECTORY_HH
#define UTILS_TEMPDIRECTORY_HH

#include <string>
#include <filesystem>

namespace unfold::utils
{
  class TempDirectory
  {
  public:
    TempDirectory();
    ~TempDirectory();

    TempDirectory(const TempDirectory &) = delete;
    TempDirectory &operator=(const TempDirectory &) = delete;
    TempDirectory(TempDirectory &&) = delete;
    TempDirectory &operator=(TempDirectory &&) = delete;

    std::filesystem::path get_path() const;

  private:
    std::string generate_random_string(std::size_t len);

  private:
    static constexpr int max_tries = 100;
    static constexpr int random_string_length = 10;
    std::filesystem::path path;
  };

} // namespace unfold::utils

#endif // UTILS_TEMPDIRECTORY_HH
