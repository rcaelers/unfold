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

#include "AppCast.hh"

#include <exception>
#include <regex>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/iostreams/stream.hpp>

namespace
{
  constexpr size_t MAX_FILENAME_LENGTH = 4096;
  constexpr size_t MAX_XML_SIZE = 10ULL * 1024 * 1024; // 10MB
  constexpr size_t MAX_ITEMS_PER_APPCAST = 1000;
  constexpr size_t MAX_ENCLOSURES_PER_ITEM = 10;
  constexpr size_t MAX_ROLLOUT_INTERVALS = 50;
  constexpr size_t MAX_STRING_LENGTH = 1024;
  constexpr size_t MAX_DESCRIPTION_LENGTH = 4096;
  constexpr size_t MAX_URL_LENGTH = 2048;
  constexpr size_t MAX_VERSION_LENGTH = 100;
  constexpr size_t MAX_SIGNATURE_LENGTH = 512;
  constexpr size_t MAX_LANGUAGE_LENGTH = 10;
  constexpr size_t MAX_OS_LENGTH = 50;
  constexpr uint64_t MAX_FILE_SIZE = 10ULL * 1024 * 1024 * 1024; // 10GB

  constexpr int MAX_ROLLOUT_DAYS = 365;
  constexpr int MAX_PERCENTAGE = 100;
  constexpr int PHASED_ROLLOUT_PHASES = 7;
  constexpr int PHASED_ROLLOUT_INCREMENT = 15;
} // namespace

AppcastReader::AppcastReader(AppcastReader::filter_func_t filter)
  : filter(filter)
{
}

std::shared_ptr<Appcast>
AppcastReader::load_from_file(const std::string &filename)
{
  if (filename.empty())
    {
      logger->error("filename cannot be empty");
      return {};
    }

  if (filename.length() > MAX_FILENAME_LENGTH)
    {
      logger->error("filename too long: {}", filename.length());
      return {};
    }

  try
    {
      boost::property_tree::ptree pt;
      read_xml(filename, pt);

      auto result = parse_channel(pt);
      if (!result)
        {
          logger->error("failed to parse channel from file: {}", filename);
          return {};
        }

      return result;
    }
  catch (std::exception &e)
    {
      logger->error("failed to load XML file {} ({})", filename, e.what());
    }
  return {};
}

std::shared_ptr<Appcast>
AppcastReader::load_from_string(const std::string &str)
{
  if (str.empty())
    {
      logger->error("input string cannot be empty");
      return {};
    }

  if (str.length() > MAX_XML_SIZE)
    {
      logger->error("input string too large: {} bytes", str.length());
      return {};
    }

  try
    {
      boost::property_tree::ptree pt;

      boost::iostreams::array_source source(str.c_str(), str.size());
      boost::iostreams::stream<boost::iostreams::array_source> stream(source);

      boost::property_tree::read_xml(stream, pt);

      auto result = parse_channel(pt);
      if (!result)
        {
          logger->error("failed to parse channel from string");
          return {};
        }

      return result;
    }
  catch (std::exception &e)
    {
      logger->error("failed to parse XML ({})", e.what());
    }
  return {};
}

std::shared_ptr<Appcast>
AppcastReader::parse_channel(boost::property_tree::ptree pt)
{
  auto appcast = std::make_shared<Appcast>();
  auto channel_pt = pt.get_child("rss.channel");

  // Parse basic channel information
  appcast->title = channel_pt.get<std::string>("title", "");
  appcast->description = channel_pt.get<std::string>("description", "");
  appcast->language = channel_pt.get<std::string>("language", "");
  appcast->link = channel_pt.get<std::string>("link", "");

  // Validate and sanitize channel data
  validate_channel(appcast);

  size_t item_count = 0;

  for (const auto &i: channel_pt)
    {
      auto [name, item_pt] = i;
      if (name == "item")
        {
          if (item_count >= MAX_ITEMS_PER_APPCAST)
            {
              logger->warn("too many items in appcast, limiting to {}", MAX_ITEMS_PER_APPCAST);
              break;
            }

          auto item = parse_item(item_pt);
          if (item && item->enclosure)
            {
              validate_item(item);
              appcast->items.push_back(item);
              item_count++;
            }
        }
    }

  logger->info("parsed appcast with {} valid items", appcast->items.size());
  return appcast;
}

std::shared_ptr<AppcastItem>
AppcastReader::parse_item(boost::property_tree::ptree item_pt)
{
  auto item = std::make_shared<AppcastItem>();

  // Parse basic item information
  item->channel = item_pt.get<std::string>("sparkle:channel", "");
  item->title = item_pt.get<std::string>("title", "");
  item->link = item_pt.get<std::string>("link", "");
  item->version = item_pt.get<std::string>("sparkle:version", "");
  item->short_version = item_pt.get<std::string>("sparkle:shortVersionString", "");
  item->description = item_pt.get<std::string>("description", "");
  item->release_notes_link = item_pt.get<std::string>("sparkle:releaseNotesLink", "");
  item->publication_date = item_pt.get<std::string>("pubDate", "");
  item->minimum_system_version = item_pt.get<std::string>("sparkle:minimumSystemVersion", "");
  item->minimum_auto_update_version = item_pt.get<std::string>("sparkle:minimumAutoupdateVersion>", "");
  item->ignore_skipped_upgrades_below_version = item_pt.get<std::string>("sparkle:ignoreSkippedUpgradesBelowVersion", "");

  // Parse rollout intervals
  item->canary_rollout_intervals = parse_rollout_intervals(item_pt);

  // Parse critical update information
  auto it_critical_update = item_pt.find("sparkle:criticalUpdate");
  if (it_critical_update != item_pt.not_found())
    {
      item->critical_update = true;
      item->critical_update_version = item_pt.get<std::string>("sparkle:criticalUpdate.<xmlattr>.sparkle:version", "");
    }

  // Parse enclosures
  size_t enclosure_count = 0;

  for (const auto &i: item_pt)
    {
      auto [name, enclosure_pt] = i;
      if (name == "enclosure")
        {
          if (enclosure_count >= MAX_ENCLOSURES_PER_ITEM)
            {
              logger->warn("too many enclosures for item, limiting to {}", MAX_ENCLOSURES_PER_ITEM);
              break;
            }

          auto enclosure = parse_enclosure(enclosure_pt);
          if (enclosure)
            {
              validate_enclosure(enclosure);
              item->enclosure = enclosure;
              if (filter(item))
                {
                  break;
                }
            }

          item->enclosure.reset();
          enclosure_count++;
        }
    }

  return item;
}

std::shared_ptr<AppcastEnclosure>
AppcastReader::parse_enclosure(boost::property_tree::ptree enclosure_pt)
{
  auto enclosure = std::make_shared<AppcastEnclosure>();

  // Parse enclosure attributes
  enclosure->url = enclosure_pt.get<std::string>("<xmlattr>.url", "");
  enclosure->signature = enclosure_pt.get<std::string>("<xmlattr>.sparkle:edSignature", "");
  enclosure->mime_type = enclosure_pt.get<std::string>("<xmlattr>.type", "");
  enclosure->installer_arguments = enclosure_pt.get<std::string>("<xmlattr>.sparkle:installerArguments", "");
  enclosure->os = enclosure_pt.get<std::string>("<xmlattr>.os", "");
  enclosure->length = enclosure_pt.get<uint64_t>("<xmlattr>.length", 0);

  return enclosure;
}

CanaryRolloutIntervals
AppcastReader::parse_rollout_intervals(boost::property_tree::ptree item_pt)
{
  auto phased_rollout_interval = item_pt.get<uint64_t>("sparkle:phasedRolloutInterval", 0);

  auto it_canaray = item_pt.find("unfold:canary");
  if (it_canaray != item_pt.not_found())
    {
      if (phased_rollout_interval != 0)
        {
          logger->warn("phased rollout interval and canary rollout intervals are mutually exclusive");
          phased_rollout_interval = 0;
        }

      auto intervals = parse_canary_rollout_intervals(it_canaray->second);
      validate_canary_rollout_intervals(intervals);
      return intervals;
    }

  if (phased_rollout_interval != 0)
    {
      CanaryRolloutIntervals intervals;
      for (int i = 1; i <= PHASED_ROLLOUT_PHASES; ++i)
        {
          intervals.emplace_back(std::chrono::seconds(phased_rollout_interval * i),
                                 i < PHASED_ROLLOUT_PHASES ? i * PHASED_ROLLOUT_INCREMENT : MAX_PERCENTAGE);
        }
      validate_rollout_intervals(intervals);
      return intervals;
    }
  return {};
}

CanaryRolloutIntervals
AppcastReader::parse_canary_rollout_intervals(boost::property_tree::ptree rollout_pt)
{
  CanaryRolloutIntervals intervals;
  std::chrono::seconds total_time{0};
  int total_percentage{0};
  size_t interval_count = 0;

  for (const auto &i: rollout_pt)
    {
      auto [name, interval_pt] = i;
      if (name == "interval")
        {
          if (interval_count >= MAX_ROLLOUT_INTERVALS)
            {
              logger->warn("too many rollout intervals, limiting to {}", MAX_ROLLOUT_INTERVALS);
              break;
            }

          auto days = interval_pt.get<int>("days", 1);
          auto percentage = interval_pt.get<int>("percentage", 0);

          total_time += std::chrono::duration_cast<std::chrono::seconds>(std::chrono::days(days));
          total_percentage += percentage;
          intervals.emplace_back(total_time, total_percentage);
          interval_count++;
        }
    }

  return intervals;
}

// Validation functions
void
AppcastReader::validate_channel(std::shared_ptr<Appcast> appcast)
{
  if (!appcast)
    {
      throw std::runtime_error("appcast is null");
    }

  sanitize_string(appcast->title, MAX_STRING_LENGTH);
  sanitize_string(appcast->description, MAX_DESCRIPTION_LENGTH);
  sanitize_string(appcast->language, MAX_LANGUAGE_LENGTH);
  sanitize_string(appcast->link, MAX_URL_LENGTH);

  if (!appcast->link.empty() && !is_valid_url(appcast->link))
    {
      throw std::runtime_error("invalid channel link URL: " + appcast->link);
    }
  
  if (!appcast->link.empty() && !is_secure_url(appcast->link))
    {
      logger->warn("channel link URL is not secure (HTTP instead of HTTPS): {}", appcast->link);
    }
}

void
AppcastReader::validate_item(std::shared_ptr<AppcastItem> item)
{
  if (!item)
    {
      throw std::runtime_error("item is null");
    }

  sanitize_string(item->channel, MAX_VERSION_LENGTH);
  sanitize_string(item->title, MAX_STRING_LENGTH);
  sanitize_string(item->link, MAX_URL_LENGTH);
  sanitize_string(item->version, MAX_VERSION_LENGTH);
  sanitize_string(item->short_version, MAX_VERSION_LENGTH);
  sanitize_string(item->description, MAX_DESCRIPTION_LENGTH);
  sanitize_string(item->release_notes_link, MAX_URL_LENGTH);
  sanitize_string(item->publication_date, MAX_VERSION_LENGTH);
  sanitize_string(item->minimum_system_version, MAX_VERSION_LENGTH);
  sanitize_string(item->minimum_auto_update_version, MAX_VERSION_LENGTH);
  sanitize_string(item->ignore_skipped_upgrades_below_version, MAX_VERSION_LENGTH);

  if (!item->version.empty() && !is_valid_version(item->version))
    {
      throw std::runtime_error("invalid version format: " + item->version);
    }

  if (!item->short_version.empty() && !is_valid_version(item->short_version))
    {
      throw std::runtime_error("invalid short version format: " + item->short_version);
    }

  if (!item->link.empty() && !is_valid_url(item->link))
    {
      throw std::runtime_error("invalid item link URL: " + item->link);
    }
  
  if (!item->link.empty() && !is_secure_url(item->link))
    {
      logger->warn("item link URL is not secure (HTTP instead of HTTPS): {}", item->link);
    }

  if (!item->release_notes_link.empty() && !is_valid_url(item->release_notes_link))
    {
      throw std::runtime_error("invalid release notes URL: " + item->release_notes_link);
    }
  
  if (!item->release_notes_link.empty() && !is_secure_url(item->release_notes_link))
    {
      logger->warn("release notes URL is not secure (HTTP instead of HTTPS): {}", item->release_notes_link);
    }

  if (item->critical_update)
    {
      sanitize_string(item->critical_update_version, MAX_VERSION_LENGTH);

      if (!item->critical_update_version.empty() && !is_valid_version(item->critical_update_version))
        {
          throw std::runtime_error("invalid critical update version: " + item->critical_update_version);
        }
    }

  if (!item->canary_rollout_intervals.empty())
    {
      validate_canary_rollout_intervals(item->canary_rollout_intervals);
    }
}

void
AppcastReader::validate_enclosure(std::shared_ptr<AppcastEnclosure> enclosure)
{
  if (!enclosure)
    {
      throw std::runtime_error("enclosure is null");
    }

  sanitize_string(enclosure->url, MAX_URL_LENGTH);
  sanitize_string(enclosure->signature, MAX_SIGNATURE_LENGTH);
  sanitize_string(enclosure->mime_type, MAX_VERSION_LENGTH);
  sanitize_string(enclosure->installer_arguments, MAX_STRING_LENGTH);
  sanitize_string(enclosure->os, MAX_OS_LENGTH);

  if (enclosure->url.empty())
    {
      throw std::runtime_error("enclosure URL is required");
    }

  if (!is_valid_url(enclosure->url))
    {
      throw std::runtime_error("invalid enclosure URL: " + enclosure->url);
    }
  
  if (!is_secure_url(enclosure->url))
    {
      logger->warn("enclosure URL is not secure (HTTP instead of HTTPS) - security risk: {}", enclosure->url);
    }

  if (!is_valid_mime_type(enclosure->mime_type))
    {
      throw std::runtime_error("invalid MIME type: " + enclosure->mime_type);
    }

  if (enclosure->length > 0 && !is_valid_length(enclosure->length))
    {
      throw std::runtime_error("suspicious file length: " + std::to_string(enclosure->length) + " bytes");
    }

  if (enclosure->signature.empty())
    {
      throw std::runtime_error("enclosure missing signature - security risk");
    }
}

void
AppcastReader::validate_individual_intervals(CanaryRolloutIntervals &intervals, bool is_canary)
{
  std::chrono::seconds last_time{0};
  auto it = intervals.begin();

  while (it != intervals.end())
    {
      auto &[duration, percentage] = *it;

      auto days = std::chrono::duration_cast<std::chrono::days>(duration).count();

      if (!is_valid_days(static_cast<int>(days)))
        {
          throw std::runtime_error("invalid days value in " + std::string(is_canary ? "canary " : "") + "rollout interval: " + std::to_string(days));
        }

      if (!is_valid_percentage(percentage))
        {
          throw std::runtime_error("invalid percentage value in " + std::string(is_canary ? "canary " : "") + "rollout interval: " + std::to_string(percentage));
        }

      // For canary rollouts, validate increasing durations
      if (is_canary && duration <= last_time)
        {
          throw std::runtime_error("canary rollout intervals must have increasing durations");
        }

      last_time = duration;
      ++it;
    }
}

void
AppcastReader::validate_canary_percentage_constraints(CanaryRolloutIntervals &intervals)
{
  int current_total = 0;

  for (const auto &[duration, percentage] : intervals)
    {
      if (current_total + (percentage - current_total) > MAX_PERCENTAGE)
        {
          throw std::runtime_error("total percentage would exceed 100% in canary rollout intervals");
        }
      current_total = percentage;
    }
}

void
AppcastReader::validate_phased_percentage_constraints(CanaryRolloutIntervals &intervals)
{
  int last_percentage = 0;

  for (auto &[duration, percentage]: intervals)
    {
      if (percentage <= last_percentage)
        {
          throw std::runtime_error("rollout percentages must be monotonically increasing");
        }
      last_percentage = percentage;
    }

  // Ensure final percentage doesn't exceed 100%
  if (intervals.back().second > MAX_PERCENTAGE)
    {
      throw std::runtime_error("final rollout percentage exceeds 100%: " + std::to_string(intervals.back().second));
    }
}

void
AppcastReader::validate_rollout_intervals(CanaryRolloutIntervals &intervals, bool is_canary)
{
  if (intervals.empty())
    {
      if (is_canary)
        {
          throw std::runtime_error("no rollout intervals found");
        }
      return;
    }

  // First pass: validate individual intervals and remove invalid ones
  validate_individual_intervals(intervals, is_canary);

  // Second pass: validate ordering and constraints
  if (!intervals.empty())
    {
      if (is_canary)
        {
          validate_canary_percentage_constraints(intervals);
        }
      else
        {
          validate_phased_percentage_constraints(intervals);
        }
    }

  // Final validation and logging
  if (intervals.empty())
    {
      if (is_canary)
        {
          throw std::runtime_error("no valid canary rollout intervals found after validation");
        }
    }
  else
    {
      if (is_canary)
        {
          int total_percentage = intervals.empty() ? 0 : intervals.back().second;
          logger->info("validated {} canary rollout intervals, total percentage: {}%", intervals.size(), total_percentage);
        }
      else
        {
          logger->info("validated {} rollout intervals", intervals.size());
        }
    }
}

void
AppcastReader::validate_canary_rollout_intervals(CanaryRolloutIntervals &intervals)
{
  validate_rollout_intervals(intervals, true);
}

bool
AppcastReader::is_valid_url(const std::string &url)
{
  if (url.empty())
    {
      return false;
    }

  auto parsed_url = parse_url(url);
  if (!parsed_url)
    {
      return false;
    }
  
  // Check that it's HTTP or HTTPS
  if (parsed_url->scheme() != "http" && parsed_url->scheme() != "https")
    {
      return false;
    }
  
  // Check that host is not empty
  if (parsed_url->host().empty())
    {
      return false;
    }
  
  return true;
}

std::optional<boost::urls::url>
AppcastReader::parse_url(const std::string &url_str)
{
  if (url_str.empty())
    {
      return std::nullopt;
    }

  try
    {
      auto result = boost::urls::parse_uri(url_str);
      if (result.has_value())
        {
          return boost::urls::url(result.value());
        }
    }
  catch (const std::exception &e)
    {
      logger->debug("URL parsing failed for '{}': {}", url_str, e.what());
    }
  
  return std::nullopt;
}

bool
AppcastReader::is_secure_url(const std::string &url_str)
{
  auto parsed_url = parse_url(url_str);
  if (!parsed_url)
    {
      return false;
    }
  
  return parsed_url->scheme() == "https";
}

bool
AppcastReader::is_valid_version(const std::string &version)
{
  if (version.empty())
    {
      return false;
    }

  return parse_version(version).has_value();
}

std::optional<semver::version>
AppcastReader::parse_version(const std::string &version_str)
{
  if (version_str.empty())
    {
      return std::nullopt;
    }

  try
    {
      semver::version parsed_version;
      if (parsed_version.from_string_noexcept(version_str))
        {
          return parsed_version;
        }
    }
  catch (const std::exception &e)
    {
      logger->debug("version parsing failed for '{}': {}", version_str, e.what());
    }

  return std::nullopt;
}

bool
AppcastReader::compare_versions(const std::string &version1, const std::string &version2)
{
  auto v1 = parse_version(version1);
  auto v2 = parse_version(version2);

  if (!v1 || !v2)
    {
      return false; // Invalid versions cannot be compared
    }

  return v1->compare(*v2) >= 0; // version1 >= version2
}

bool
AppcastReader::is_valid_percentage(int percentage)
{
  return percentage >= 0 && percentage <= MAX_PERCENTAGE;
}

bool
AppcastReader::is_valid_days(int days)
{
  return days > 0 && days <= MAX_ROLLOUT_DAYS;
}

bool
AppcastReader::is_valid_length(uint64_t length)
{
  return length > 0 && length <= MAX_FILE_SIZE;
}

bool
AppcastReader::is_valid_mime_type(const std::string &mime_type)
{
  if (mime_type.empty())
    {
      return true;
    }

  std::regex mime_pattern(R"(^[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^]*\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^]*$)");
  return std::regex_match(mime_type, mime_pattern);
}

void
AppcastReader::sanitize_string(std::string &str, size_t max_length)
{
  str.erase(std::remove(str.begin(), str.end(), '\0'), str.end());
  if (str.length() > max_length)
    {
      str = str.substr(0, max_length);
    }
}

std::string
AppcastReader::get_url_domain(const std::string &url_str)
{
  auto parsed_url = parse_url(url_str);
  if (!parsed_url)
    {
      return "";
    }
  
  return std::string(parsed_url->host());
}
