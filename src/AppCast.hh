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

#include <memory>
#include <string>
#include <vector>

#include <boost/property_tree/ptree.hpp>

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
  uint64_t phased_rollout_interval{0};               // TODO: not supported

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
  AppcastReader(filter_func_t filter);

  std::shared_ptr<Appcast> load_from_file(const std::string &filename);
  std::shared_ptr<Appcast> load_from_string(const std::string &str);

private:
  std::shared_ptr<Appcast> parse_channel(boost::property_tree::ptree pt);
  std::shared_ptr<AppcastItem> parse_item(boost::property_tree::ptree item_pt);
  std::shared_ptr<AppcastEnclosure> parse_enclosure(boost::property_tree::ptree enclosure_pt);

private:
  std::shared_ptr<spdlog::logger> logger{unfold::utils::Logging::create("unfold:appcast")};
  filter_func_t filter;
};

#endif // APPCAST_HH
