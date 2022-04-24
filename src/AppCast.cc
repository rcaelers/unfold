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

#include <iostream>
#include <boost/property_tree/xml_parser.hpp>

std::shared_ptr<Appcast>
AppcastReader::load(const std::string &filename)
{
  using boost::property_tree::ptree;
  ptree pt;

  read_xml(filename, pt);

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
          appcast->items.push_back(item);
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
  item->phased_rollout_interval = item_pt.get<uint64_t>("sparkle:phasedRolloutInterval", 0);

  auto it = item_pt.find("sparkle:criticalUpdate");
  if (it != item_pt.not_found())
    {
      item->critical_update = true;
      item->critical_update_version = item_pt.get<std::string>("sparkle:criticalUpdate.<xmlattr>.sparkle:version", "");
    }

  for (const auto &i: item_pt)
    {
      auto [name, enclosure_pt] = i;
      if (name == "sparkle:enclosure")
        {
          auto enclosure = parse_enclosure(enclosure_pt);
          item->enclosures.push_back(enclosure);
        }
    }

  return item;
}

std::shared_ptr<AppcastEnclosure>
AppcastReader::parse_enclosure(boost::property_tree::ptree enclosure_pt)
{
  auto enclosure = std::make_shared<AppcastEnclosure>();

  enclosure->url = enclosure_pt.get<std::string>("<xmlattr>.url", "");
  enclosure->signature = enclosure_pt.get<std::string>("<xmlattr>,sparkle:edSignature", "");
  enclosure->mime_type = enclosure_pt.get<std::string>("<xmlattr>.type", "");
  enclosure->install_arguments = enclosure_pt.get<std::string>("installArguments", "");
  enclosure->os = enclosure_pt.get<std::string>("<xmlattr>.os", "");
  enclosure->length = enclosure_pt.get<uint64_t>("<xmlattr>.length", 0);

  return enclosure;
}
