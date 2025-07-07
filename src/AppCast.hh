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
#include <boost/outcome/std_result.hpp>

#include "utils/Logging.hh"
#include "crypto/XMLDSigVerifier.hh"

namespace outcome = boost::outcome_v2;

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

  outcome::std_result<void> add_xmldsig_public_key(const std::string &key_name, const std::string &public_key_pem);
  void clear_xmldsig_trusted_keys();
  void set_xmldsig_verification_enabled(bool enabled);

  std::shared_ptr<Appcast> load_from_file(const std::string &filename);
  std::shared_ptr<Appcast> load_from_string(const std::string &str);

private:
  std::string read_file_content(const std::string &filename);
  std::shared_ptr<Appcast> process_xml_content(const std::string &xml_content);
  std::shared_ptr<Appcast> parse_xml_content(const std::string &xml_content);
  void verify_xml_signature(const std::string &xml_content);

  std::shared_ptr<Appcast> parse_channel(boost::property_tree::ptree pt);
  std::shared_ptr<AppcastItem> parse_item(boost::property_tree::ptree item_pt);
  std::shared_ptr<AppcastEnclosure> parse_enclosure(boost::property_tree::ptree enclosure_pt);
  CanaryRolloutIntervals parse_rollout_intervals(boost::property_tree::ptree pt);
  CanaryRolloutIntervals parse_canary_rollout_intervals(boost::property_tree::ptree rollout_pt);

  void validate_channel(std::shared_ptr<Appcast> appcast);
  void validate_item(std::shared_ptr<AppcastItem> item);
  void validate_enclosure(std::shared_ptr<AppcastEnclosure> enclosure);
  void validate_rollout_intervals(CanaryRolloutIntervals &intervals, bool is_canary = false);
  void validate_canary_rollout_intervals(CanaryRolloutIntervals &intervals);
  void validate_individual_intervals(CanaryRolloutIntervals &intervals, bool is_canary);
  void validate_canary_percentage_constraints(CanaryRolloutIntervals &intervals);
  void validate_phased_percentage_constraints(CanaryRolloutIntervals &intervals);

  bool is_valid_url(const std::string &url);
  bool is_valid_version(const std::string &version);
  bool is_valid_percentage(int percentage);
  bool is_valid_days(int days);
  bool is_valid_length(uint64_t length);
  bool is_valid_mime_type(const std::string &mime_type);
  bool is_valid_ed_signature(const std::string &signature);
  void sanitize_string(std::string &str, size_t max_length);

  std::optional<boost::urls::url> parse_url(const std::string &url_str);
  bool is_secure_url(const std::string &url_str);

private:
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:appcast")};
  filter_func_t filter;
  std::unique_ptr<unfold::crypto::XMLDSigVerifier> xmldsig_verifier;
  bool xmldsig_verification_enabled = false;
};

#endif // APPCAST_HH
