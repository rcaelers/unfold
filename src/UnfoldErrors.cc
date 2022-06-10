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

#include "unfold/UnfoldErrors.hh"

using namespace unfold;

namespace
{
  class UnfoldErrorCategory : public std::error_category
  {
  public:
    const char *name() const noexcept final
    {
      return "unfold";
    }

    std::string message(int ev) const final
    {
      switch (static_cast<UnfoldErrc>(ev))
        {
        case UnfoldErrc::Success:
          return "success";
        case UnfoldErrc::InvalidArgument:
          return "invalid argument";
        case UnfoldErrc::InvalidAppcast:
          return "invalid appcast";
        case UnfoldErrc::AppcastDownloadFailed:
          return "failed to download appcast";
        case UnfoldErrc::InstallerDownloadFailed:
          return "failed to download installer";
        case UnfoldErrc::InstallerVerificationFailed:
          return "failed to validate installer integrity";
        case UnfoldErrc::InstallerExecutionFailed:
          return "failed to execute installer";
        case UnfoldErrc::InternalError:
          return "internal error";
        }
    }
  };

  const UnfoldErrorCategory globalUnfoldErrorCategory{};
} // namespace

std::error_code
unfold::make_error_code(UnfoldErrc ec)
{
  return std::error_code{static_cast<int>(ec), globalUnfoldErrorCategory};
}
