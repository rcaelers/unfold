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

#ifndef APPCAST_HH
#define APPCAST_HH

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <boost/property_tree/ptree.hpp>
#include <boost/url.hpp>

#include "semver.hpp"
#include "utils/Logging.hh"

struct AppcastEnclosure
{
  std::string url;
  std::string signature;
  uint64_t length = 0;
  std::string mime_type;
  std::string installer_arguments;
  std::string os;
};

using CanaryRolloutIntervals = std::vector<std::pair<std::chrono::seconds, int>>;

struct AppcastItem
{
  std::string channel;
  std::string title;
  std::string link;
  std::string version;
  std::string short_version;
  std::string description;
  std::string release_notes_link;
  std::string publication_date;
  std::string minimum_system_version;
  std::string minimum_auto_update_version;           // TODO: not supported
  std::string ignore_skipped_upgrades_below_version; // TODO: not supported
  bool critical_update{false};                       // TODO: not supported
  std::string critical_update_version;               // TODO: not supported
  CanaryRolloutIntervals canary_rollout_intervals;

  std::shared_ptr<AppcastEnclosure> enclosure;
};

struct Appcast
{
  std::string title;
  std::string description;
  std::string language;
  std::string link;
  std::vector<std::shared_ptr<AppcastItem>> items;
};

class AppcastReader
{
public:
  using filter_func_t = std::function<bool(std::shared_ptr<AppcastItem>)>;
  explicit AppcastReader(filter_func_t filter);

  std::shared_ptr<Appcast> load_from_file(const std::string &filename);
  std::shared_ptr<Appcast> load_from_string(const std::string &str);

private:
  std::shared_ptr<Appcast> parse_channel(boost::property_tree::ptree pt);
  std::shared_ptr<AppcastItem> parse_item(boost::property_tree::ptree item_pt);
  std::shared_ptr<AppcastEnclosure> parse_enclosure(boost::property_tree::ptree enclosure_pt);
  CanaryRolloutIntervals parse_rollout_intervals(boost::property_tree::ptree pt);
  CanaryRolloutIntervals parse_canary_rollout_intervals(boost::property_tree::ptree rollout_pt);

  void validate_channel(std::shared_ptr<Appcast> appcast);  // throws on validation error
  void validate_item(std::shared_ptr<AppcastItem> item);    // throws on validation error  
  void validate_enclosure(std::shared_ptr<AppcastEnclosure> enclosure); // throws on validation error
  void validate_rollout_intervals(CanaryRolloutIntervals &intervals, bool is_canary = false); // throws on validation error
  void validate_canary_rollout_intervals(CanaryRolloutIntervals &intervals); // throws on validation error
  void validate_individual_intervals(CanaryRolloutIntervals &intervals, bool is_canary); // throws on validation error
  void validate_canary_percentage_constraints(CanaryRolloutIntervals &intervals); // throws on validation error
  void validate_phased_percentage_constraints(CanaryRolloutIntervals &intervals); // throws on validation error

  bool is_valid_url(const std::string &url);
  bool is_valid_version(const std::string &version);
  bool is_valid_percentage(int percentage);
  bool is_valid_days(int days);
  bool is_valid_length(uint64_t length);
  bool is_valid_mime_type(const std::string &mime_type);
  void sanitize_string(std::string &str, size_t max_length);

  // URL parsing helpers
  std::optional<boost::urls::url> parse_url(const std::string &url_str);
  bool is_secure_url(const std::string &url_str); // checks if URL uses HTTPS
  std::string get_url_domain(const std::string &url_str); // extracts domain from URL

  // Version comparison helpers
  std::optional<semver::version> parse_version(const std::string &version_str);
  bool compare_versions(const std::string &version1, const std::string &version2); // returns true if version1 >= version2


private:
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:appcast")};
  filter_func_t filter;
};

#endif // APPCAST_HH
