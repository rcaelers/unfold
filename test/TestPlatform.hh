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

#ifndef TEST_PLATFORM_HH
#define TEST_PLATFORM_HH

#include <memory>
#include <string>

#include "Platform.hh"

#include "utils/Logging.hh"

class TestPlatform : public Platform
{
public:
  TestPlatform() = default;

  bool is_supported_os(const std::string &os) override;
  bool is_supported_os_version(const std::string &minimum_version) override;
  void execute(const std::string &exe, std::vector<std::string> args) override;

private:
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:platform")};
};

#endif // WINDOWS_PLATFORM_HH
