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

#ifndef INSTALLER_HH
#define INSTALLER_HH

#include <memory>

#include "unfold/Unfold.hh"
#include "AppCast.hh"

namespace outcome = boost::outcome_v2;

class Installer
{
public:
  virtual ~Installer() = default;

  virtual void set_download_progress_callback(unfold::Unfold::download_progress_callback_t callback) = 0;
  virtual void set_installer_validation_callback(unfold::Unfold::installer_validation_callback_t callback) = 0;
  virtual boost::asio::awaitable<outcome::std_result<void>> install(std::shared_ptr<AppcastItem> item) = 0;
};

#endif // INSTALLER_HH
