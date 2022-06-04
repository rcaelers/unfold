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

#ifndef UNFOLD_UNFOLD_HH
#define UNFOLD_UNFOLD_HH

#include <memory>
#include <string>
#include <chrono>
#include <list>

#include <boost/outcome/std_result.hpp>
#include <boost/asio.hpp>

#include "utils/IOContext.hh"

namespace unfold
{
  struct UpdateReleaseNotes
  {
    std::string version;
    std::string date;
    // TODO: std::chrono::system_clock::time_point date;
    std::string markdown;
  };

  struct UpdateInfo
  {
    std::string title;
    std::string version;
    std::string current_version;
    std::list<UpdateReleaseNotes> release_notes;
  };

  enum class UpdateResponse
  {
    Install,
    Later,
    Skip,
  };

  namespace outcome = boost::outcome_v2;

  class Unfold
  {
  public:
    Unfold() = default;
    virtual ~Unfold() = default;

    using update_available_callback_t = std::function<boost::asio::awaitable<UpdateResponse>()>;

    static std::shared_ptr<Unfold> create(unfold::utils::IOContext &io_context);

    virtual outcome::std_result<void> set_appcast(const std::string &url) = 0;
    virtual outcome::std_result<void> set_current_version(const std::string &version) = 0;
    virtual outcome::std_result<void> set_signature_verification_key(const std::string &key) = 0;
    virtual outcome::std_result<void> set_certificate(const std::string &cert) = 0;
    virtual void set_periodic_update_check_enabled(bool enabled) = 0;
    virtual void set_periodic_update_check_interval(std::chrono::seconds interval) = 0;
    virtual void set_configuration_prefix(const std::string &prefix) = 0;
    virtual void set_update_available_callback(update_available_callback_t callback) = 0;
    virtual std::chrono::system_clock::time_point get_last_update_check_time() = 0;

    // TODO: custom version comparator API

    virtual boost::asio::awaitable<outcome::std_result<bool>> check_for_updates() = 0;
    virtual boost::asio::awaitable<outcome::std_result<void>> install_update() = 0;

    virtual std::shared_ptr<unfold::UpdateInfo> get_update_info() const = 0;
  };
} // namespace unfold

#endif // UNFOLD_UNFOLD_HH
