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
#include <boost/property_tree/xml_parser.hpp>
#include <boost/iostreams/stream.hpp>

AppcastReader::AppcastReader(AppcastReader::filter_func_t filter)
  : filter(filter)
{
}

std::shared_ptr<Appcast>
AppcastReader::load_from_file(const std::string &filename)
{
  try
    {
      boost::property_tree::ptree pt;
      read_xml(filename, pt);
      return parse_channel(pt);
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
  try
    {
      boost::property_tree::ptree pt;

      boost::iostreams::array_source source(str.c_str(), str.size());
      boost::iostreams::stream<boost::iostreams::array_source> stream(source);

      boost::property_tree::read_xml(stream, pt);
      return parse_channel(pt);
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

  appcast->title = channel_pt.get<std::string>("title", "");
  appcast->description = channel_pt.get<std::string>("description", "");
  appcast->language = channel_pt.get<std::string>("language", "");
  appcast->link = channel_pt.get<std::string>("link", "");

  for (const auto &i: channel_pt)
    {
      auto [name, item_pt] = i;
      if (name == "item")
        {
          auto item = parse_item(item_pt);
          if (item->enclosure)
            {
              appcast->items.push_back(item);
            }
        }
    }
  return appcast;
}

std::shared_ptr<AppcastItem>
AppcastReader::parse_item(boost::property_tree::ptree item_pt)
{
  auto item = std::make_shared<AppcastItem>();

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
  item->canary_rollout_intervals = parse_rollout_intervals(item_pt);

  auto it_critical_update = item_pt.find("sparkle:criticalUpdate");
  if (it_critical_update != item_pt.not_found())
    {
      item->critical_update = true;
      item->critical_update_version = item_pt.get<std::string>("sparkle:criticalUpdate.<xmlattr>.sparkle:version", "");
    }

  for (const auto &i: item_pt)
    {
      auto [name, enclosure_pt] = i;
      if (name == "enclosure")
        {
          item->enclosure = parse_enclosure(enclosure_pt);
          if (filter(item))
            {
              break;
            }

          item->enclosure.reset();
        }
    }

  return item;
}

std::shared_ptr<AppcastEnclosure>
AppcastReader::parse_enclosure(boost::property_tree::ptree enclosure_pt)
{
  auto enclosure = std::make_shared<AppcastEnclosure>();

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

      return parse_canary_rollout_intervals(it_canaray->second);
    }

  if (phased_rollout_interval != 0)
    {
      CanaryRolloutIntervals intervals;
      for (int i = 1; i <= 7; ++i)
        {
          intervals.emplace_back(std::chrono::seconds(phased_rollout_interval * i), i < 7 ? i * 15 : 100);
        }
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

  for (const auto &i: rollout_pt)
    {
      auto [name, interval_pt] = i;
      if (name == "interval")
        {
          auto days = interval_pt.get<int>("days", 1);
          auto percentage = interval_pt.get<int>("percentage", 0);
          total_time += std::chrono::duration_cast<std::chrono::seconds>(std::chrono::days(days));
          total_percentage += percentage;
          intervals.emplace_back(total_time, total_percentage);
        }
    }

  return intervals;
}
