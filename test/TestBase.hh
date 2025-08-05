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

#ifndef TESTBASE_HH
#define TESTBASE_HH

#include "utils/Enum.hh"
#include "unfold/Unfold.hh"

template<>
struct unfold::utils::enum_traits<unfold::UpdateStage>
{
  static constexpr auto min = unfold::UpdateStage::DownloadInstaller;
  static constexpr auto max = unfold::UpdateStage::RunInstaller;
  static constexpr auto linear = true;

  static constexpr std::array<std::pair<std::string_view, unfold::UpdateStage>, 3> names{{{"Download", unfold::UpdateStage::DownloadInstaller},
                                                                                          {"Run", unfold::UpdateStage::RunInstaller},
                                                                                          {"Verify", unfold::UpdateStage::VerifyInstaller}}};
};

namespace unfold
{
  inline std::ostream &operator<<(std::ostream &os, unfold::UpdateStage e)
  {
    os << unfold::utils::enum_to_string(e);
    return os;
  }
} // namespace unfold

#endif // TESTBASE_HH
