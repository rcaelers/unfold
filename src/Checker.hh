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

#ifndef CHECKER_HH
#define CHECKER_HH

#include <chrono>
#include <string>

#include "unfold/Unfold.hh"

#include "AppCast.hh"

namespace outcome = boost::outcome_v2;

class Checker
{
public:
  virtual ~Checker() = default;
  virtual boost::asio::awaitable<outcome::std_result<bool>> check_for_update() = 0;
  virtual outcome::std_result<void> set_appcast(const std::string &url) = 0;
  virtual outcome::std_result<void> set_current_version(const std::string &version) = 0;
  virtual outcome::std_result<void> set_allowed_channels(const std::vector<std::string> &channels) = 0;
  virtual void set_update_validation_callback(unfold::Unfold::update_validation_callback_t callback) = 0;
  virtual std::shared_ptr<unfold::UpdateInfo> get_update_info() const = 0;
  virtual std::shared_ptr<AppcastItem> get_selected_update() const = 0;
  virtual std::chrono::seconds get_rollout_delay_for_priority(int priority) const = 0;
  virtual std::chrono::system_clock::time_point get_earliest_rollout_time_for_priority(int priority) const = 0;
};

#endif // CHECKER_HH
