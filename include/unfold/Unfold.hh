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

#include <boost/outcome/std_result.hpp>
#include <boost/asio.hpp>

namespace unfold
{
  struct Appcast
  {
    std::string title;
    std::string link;
    std::string version;
    std::string short_version;
    std::string description;
    std::string release_notes_link;
    std::string publication_date;
    std::string minimum_auto_update_version;
    std::string ignore_skipped_upgrades_below_version;
    bool critical_update{false};
    std::string critical_update_version;
    uint64_t phased_rollout_interval{0};

    std::string url;
    std::string signature;
    uint64_t length = 0;
    std::string mime_type;
    std::string install_arguments;
    std::string os;
  };

  namespace outcome = boost::outcome_v2;

  class Unfold
  {
  public:
    Unfold() = default;
    virtual ~Unfold() = default;

    static std::shared_ptr<Unfold> create();

    virtual outcome::std_result<void> set_appcast(const std::string &url) = 0;
    virtual outcome::std_result<void> set_current_version(const std::string &version) = 0;
    virtual outcome::std_result<void> set_signature_verification_key(const std::string &key) = 0;
    virtual outcome::std_result<void> set_certificate(const std::string &cert) = 0;

    // TODO: custom version comparator API

    virtual boost::asio::awaitable<outcome::std_result<void>> check() = 0;
    virtual boost::asio::awaitable<outcome::std_result<void>> install() = 0;
  };
} // namespace unfold
  
#endif // UNFOLD_UNFOLD_HH
