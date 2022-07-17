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

#include <boost/test/unit_test.hpp>
#include <spdlog/spdlog.h>

#include "Fixture.hpp"
#include "AppCast.hh"

BOOST_FIXTURE_TEST_SUITE(unfold_appcast_test, Fixture)

BOOST_AUTO_TEST_CASE(appcast_load_from_string)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string appcast_str =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\"\n"
    "    xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Workrave Test Appcast</title>\n"
    "        <description>Most recent updates to Workrave Test</description>\n"
    "        <language>en</language>\n"
    "        <link>https://workrave.org/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:channel>release</sparkle:channel>\n"
    "            <sparkle:version>1.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun Apr 17 19:30:14 CEST 2022</pubDate>\n"
    "            <enclosure url=\"http://localhost:1337/v2.zip\" sparkle:edSignature=\"xx\" length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(appcast_str);

  BOOST_CHECK_EQUAL(appcast->title, "Workrave Test Appcast");
  BOOST_CHECK_EQUAL(appcast->description, "Most recent updates to Workrave Test");
  BOOST_CHECK_EQUAL(appcast->language, "en");
  BOOST_CHECK_EQUAL(appcast->link, "https://workrave.org/");

  BOOST_CHECK_EQUAL(appcast->items.size(), 1);

  BOOST_CHECK_EQUAL(appcast->items[0]->channel, "release");
  BOOST_CHECK_EQUAL(appcast->items[0]->title, "Version 1.0");
  BOOST_CHECK_EQUAL(appcast->items[0]->link, "https://workrave.org");
  BOOST_CHECK_EQUAL(appcast->items[0]->version, "1.0");
  BOOST_CHECK_EQUAL(appcast->items[0]->short_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->description, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->release_notes_link, "https://workrave.org/v1.html");
  BOOST_CHECK_EQUAL(appcast->items[0]->publication_date, "Sun Apr 17 19:30:14 CEST 2022");
  BOOST_CHECK_EQUAL(appcast->items[0]->minimum_system_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->minimum_auto_update_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->ignore_skipped_upgrades_below_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->critical_update, false);
  BOOST_CHECK_EQUAL(appcast->items[0]->critical_update_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->phased_rollout_interval, 0);
}

BOOST_AUTO_TEST_CASE(appcast_load_from_file)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_file("okappcast.xml");

  BOOST_CHECK_EQUAL(appcast->title, "Workrave Test Appcast");
  BOOST_CHECK_EQUAL(appcast->description, "Most recent updates to Workrave Test");
  BOOST_CHECK_EQUAL(appcast->language, "en");
  BOOST_CHECK_EQUAL(appcast->link, "https://workrave.org/");

  BOOST_CHECK_EQUAL(appcast->items.size(), 2);

  BOOST_CHECK_EQUAL(appcast->items[0]->channel, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->title, "Version 1.0");
  BOOST_CHECK_EQUAL(appcast->items[0]->link, "https://workrave.org");
  BOOST_CHECK_EQUAL(appcast->items[0]->version, "1.0");
  BOOST_CHECK_EQUAL(appcast->items[0]->short_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->description, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->release_notes_link, "https://workrave.org/v1.html");
  BOOST_CHECK_EQUAL(appcast->items[0]->publication_date, "Sun Apr 17 19:30:14 CEST 2022");
  BOOST_CHECK_EQUAL(appcast->items[0]->minimum_system_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->minimum_auto_update_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->ignore_skipped_upgrades_below_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->critical_update, false);
  BOOST_CHECK_EQUAL(appcast->items[0]->critical_update_version, "");
  BOOST_CHECK_EQUAL(appcast->items[0]->phased_rollout_interval, 0);

  BOOST_CHECK_EQUAL(appcast->items[1]->channel, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->title, "Version 2.0");
  BOOST_CHECK_EQUAL(appcast->items[1]->link, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->version, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->short_version, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->description, "Version 2 update");
  BOOST_CHECK_EQUAL(appcast->items[1]->release_notes_link, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->publication_date, "Sun Apr 17 19:30:14 CEST 2022");
  BOOST_CHECK_EQUAL(appcast->items[1]->minimum_system_version, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->minimum_auto_update_version, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->ignore_skipped_upgrades_below_version, "");
  BOOST_CHECK_EQUAL(appcast->items[1]->critical_update, true);
  BOOST_CHECK_EQUAL(appcast->items[1]->critical_update_version, "1.5");
  BOOST_CHECK_EQUAL(appcast->items[1]->phased_rollout_interval, 0);
}

BOOST_AUTO_TEST_CASE(appcast_load_invalid_from_string)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string appcast_str = "Foo\n";

  auto appcast = reader->load_from_string(appcast_str);
  BOOST_CHECK_EQUAL(appcast.get(), nullptr);
}

BOOST_AUTO_TEST_CASE(appcast_load_invalid_from_file)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_file("invalidappcast.xml");
  BOOST_CHECK_EQUAL(appcast.get(), nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
