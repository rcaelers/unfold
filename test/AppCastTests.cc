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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <fstream>

#include <spdlog/spdlog.h>

#include "AppCast.hh"

TEST(AppCastTest, LoadFromString)
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
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>https://workrave.org/v1.html</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"http://localhost:1337/v2.zip\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(appcast_str);

  EXPECT_EQ(appcast->title, "Workrave Test Appcast");
  EXPECT_EQ(appcast->description, "Most recent updates to Workrave Test");
  EXPECT_EQ(appcast->language, "en");
  EXPECT_EQ(appcast->link, "https://workrave.org/");

  EXPECT_EQ(appcast->items.size(), 1);

  EXPECT_EQ(appcast->items[0]->channel, "release");
  EXPECT_EQ(appcast->items[0]->title, "Version 1.0");
  EXPECT_EQ(appcast->items[0]->link, "https://workrave.org");
  EXPECT_EQ(appcast->items[0]->version, "1.0.0");
  EXPECT_EQ(appcast->items[0]->short_version, "");
  EXPECT_EQ(appcast->items[0]->description, "");
  EXPECT_EQ(appcast->items[0]->release_notes_link, "https://workrave.org/v1.html");
  EXPECT_EQ(appcast->items[0]->publication_date, "Sun, 17 Apr 2022 19:30:14 +0200");
  EXPECT_EQ(appcast->items[0]->minimum_system_version, "");
  EXPECT_EQ(appcast->items[0]->minimum_auto_update_version, "");
  EXPECT_EQ(appcast->items[0]->ignore_skipped_upgrades_below_version, "");
  EXPECT_EQ(appcast->items[0]->critical_update, false);
  EXPECT_EQ(appcast->items[0]->critical_update_version, "");
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals.size(), 0);
}

TEST(AppCastTest, LoadFromFile)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_file("okappcast.xml");

  EXPECT_EQ(appcast->title, "Workrave Test Appcast");
  EXPECT_EQ(appcast->description, "Most recent updates to Workrave Test");
  EXPECT_EQ(appcast->language, "en");
  EXPECT_EQ(appcast->link, "https://workrave.org/");

  EXPECT_EQ(appcast->items.size(), 2);

  EXPECT_EQ(appcast->items[0]->channel, "");
  EXPECT_EQ(appcast->items[0]->title, "Version 1.0");
  EXPECT_EQ(appcast->items[0]->link, "https://workrave.org");
  EXPECT_EQ(appcast->items[0]->version, "1.0.0");
  EXPECT_EQ(appcast->items[0]->short_version, "");
  EXPECT_EQ(appcast->items[0]->description, "");
  EXPECT_EQ(appcast->items[0]->release_notes_link, "https://workrave.org/v1.html");
  EXPECT_EQ(appcast->items[0]->publication_date, "Sun, 17 Apr 2022 19:30:14 +0200");
  EXPECT_EQ(appcast->items[0]->minimum_system_version, "");
  EXPECT_EQ(appcast->items[0]->minimum_auto_update_version, "");
  EXPECT_EQ(appcast->items[0]->ignore_skipped_upgrades_below_version, "");
  EXPECT_EQ(appcast->items[0]->critical_update, false);
  EXPECT_EQ(appcast->items[0]->critical_update_version, "");
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals.size(), 0);

  EXPECT_EQ(appcast->items[1]->channel, "");
  EXPECT_EQ(appcast->items[1]->title, "Version 2.0");
  EXPECT_EQ(appcast->items[1]->link, "");
  EXPECT_EQ(appcast->items[1]->version, "2.0.0");
  EXPECT_EQ(appcast->items[1]->short_version, "");
  EXPECT_EQ(appcast->items[1]->description, "Version 2 update");
  EXPECT_EQ(appcast->items[1]->release_notes_link, "");
  EXPECT_EQ(appcast->items[1]->publication_date, "Sun, 17 Apr 2022 19:30:14 +0200");
  EXPECT_EQ(appcast->items[1]->minimum_system_version, "");
  EXPECT_EQ(appcast->items[1]->minimum_auto_update_version, "");
  EXPECT_EQ(appcast->items[1]->ignore_skipped_upgrades_below_version, "");
  EXPECT_EQ(appcast->items[1]->critical_update, true);
  EXPECT_EQ(appcast->items[1]->critical_update_version, "1.5.0");
  EXPECT_EQ(appcast->items[1]->canary_rollout_intervals.size(), 0);
}

TEST(AppCastTest, LoadInvalidFromString)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string appcast_str = "Foo\n";

  auto appcast = reader->load_from_string(appcast_str);
  EXPECT_EQ(appcast.get(), nullptr);
}

TEST(AppCastTest, LoadInvalidFromFile)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_file("invalidappcast.xml");
  EXPECT_EQ(appcast.get(), nullptr);
}

TEST(AppCastTest, Canary)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_file("appcast-canary.xml");

  EXPECT_EQ(appcast->title, "Workrave Test Appcast");
  EXPECT_EQ(appcast->description, "Most recent updates to Workrave Test");
  EXPECT_EQ(appcast->language, "en");
  EXPECT_EQ(appcast->link, "https://workrave.org/");

  EXPECT_EQ(appcast->items.size(), 2);

  EXPECT_EQ(appcast->items[0]->channel, "");
  EXPECT_EQ(appcast->items[0]->title, "Version 1.0");
  EXPECT_EQ(appcast->items[0]->link, "https://workrave.org");
  EXPECT_EQ(appcast->items[0]->version, "1.0.0");
  EXPECT_EQ(appcast->items[0]->short_version, "");
  EXPECT_EQ(appcast->items[0]->description, "");
  EXPECT_EQ(appcast->items[0]->release_notes_link, "https://workrave.org/v1.html");
  EXPECT_EQ(appcast->items[0]->publication_date, "Sun, 17 Apr 2022 19:30:14 +0200");
  EXPECT_EQ(appcast->items[0]->minimum_system_version, "");
  EXPECT_EQ(appcast->items[0]->minimum_auto_update_version, "");
  EXPECT_EQ(appcast->items[0]->ignore_skipped_upgrades_below_version, "");
  EXPECT_EQ(appcast->items[0]->critical_update, false);
  EXPECT_EQ(appcast->items[0]->critical_update_version, "");

  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals.size(), 3);
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[0].first,
            std::chrono::seconds(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::days(2))));
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[0].second, 10);
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[1].first,
            std::chrono::seconds(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::days(5))));
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[1].second, 25);
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[2].first,
            std::chrono::seconds(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::days(10))));
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[2].second, 55);

  EXPECT_EQ(appcast->items[1]->channel, "");
  EXPECT_EQ(appcast->items[1]->title, "Version 2.0");
  EXPECT_EQ(appcast->items[1]->link, "");
  EXPECT_EQ(appcast->items[1]->version, "2.0.0");
  EXPECT_EQ(appcast->items[1]->short_version, "");
  EXPECT_EQ(appcast->items[1]->description, "Version 2 update");
  EXPECT_EQ(appcast->items[1]->release_notes_link, "");
  EXPECT_EQ(appcast->items[1]->publication_date, "Sun, 17 Apr 2022 19:30:14 +0200");
  EXPECT_EQ(appcast->items[1]->minimum_system_version, "");
  EXPECT_EQ(appcast->items[1]->minimum_auto_update_version, "");
  EXPECT_EQ(appcast->items[1]->ignore_skipped_upgrades_below_version, "");
  EXPECT_EQ(appcast->items[1]->critical_update, true);
  EXPECT_EQ(appcast->items[1]->critical_update_version, "1.5.0");
  EXPECT_EQ(appcast->items[1]->canary_rollout_intervals.size(), 3);
}

TEST(AppCastTest, CanaryError)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_file("appcast-canary-error.xml");

  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals.size(), 3);
}

TEST(AppCastTest, CanarySparkle)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_file("appcast-canary-sparkle.xml");

  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals.size(), 7);
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[0].first, std::chrono::days(2));
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[0].second, 15);
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[1].first, std::chrono::days(4));
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[1].second, 30);
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[2].first, std::chrono::days(6));
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[2].second, 45);
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[3].first, std::chrono::days(8));
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[3].second, 60);
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[4].first, std::chrono::days(10));
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[4].second, 75);
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[5].first, std::chrono::days(12));
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[5].second, 90);
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[6].first, std::chrono::days(14));
  EXPECT_EQ(appcast->items[0]->canary_rollout_intervals[6].second, 100);
}

TEST(AppCastTest, SignatureValidation)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  // Test 1: Valid 64-byte signature should pass
  std::string valid_appcast =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(valid_appcast);
  EXPECT_NE(appcast, nullptr);
  EXPECT_EQ(appcast->items.size(), 1);
  EXPECT_NE(appcast->items[0]->enclosure, nullptr);
  EXPECT_EQ(appcast->items[0]->enclosure->signature,
            "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==");

  // Test 2: Invalid short signature should fail
  std::string invalid_short_signature =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"dGVzdA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  EXPECT_EQ(reader->load_from_string(invalid_short_signature), nullptr);

  // Test 3: Invalid base64 signature should fail
  std::string invalid_base64_signature =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"invalid@base64!\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  EXPECT_EQ(reader->load_from_string(invalid_base64_signature), nullptr);

  // Test 4: Missing signature should fail
  std::string missing_signature =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  EXPECT_EQ(reader->load_from_string(missing_signature), nullptr);
}

// Tests for 100% branch coverage

TEST(AppCastTest, EmptyFilename)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_file("");
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, FilenameToolong)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  const size_t max_filename_plus_one = 5000; // Exceeds MAX_FILENAME_LENGTH (4096)
  std::string long_filename(max_filename_plus_one, 'a');
  auto appcast = reader->load_from_file(long_filename);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, EmptyString)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_string("");
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, StringTooLarge)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  const size_t kb_size = 1024;
  const size_t mb_size = kb_size * kb_size;
  const size_t large_size = 11 * mb_size; // Exceeds MAX_XML_SIZE (10MB)
  std::string large_string(large_size, 'a');
  auto appcast = reader->load_from_string(large_string);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, NonExistentFile)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  auto appcast = reader->load_from_file("non_existent_file.xml");
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, MalformedXML)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string malformed_xml = "<?xml version='1.0'?><rss><channel><unclosed_tag></channel></rss>";
  auto appcast = reader->load_from_string(malformed_xml);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, MissingChannel)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string no_channel = "<?xml version='1.0'?><rss version='2.0'></rss>";
  auto appcast = reader->load_from_string(no_channel);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, InvalidChannelLink)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string invalid_link =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>invalid://url</link>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_link);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, HttpChannelLink)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string http_link =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>http://example.com/</link>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(http_link);
  EXPECT_NE(appcast, nullptr);
  EXPECT_EQ(appcast->link, "http://example.com/");
}

TEST(AppCastTest, TooManyItems)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string many_items_start =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n";

  std::string many_items_end = "    </channel>\n</rss>\n";

  std::string items;
  // Create more than MAX_ITEMS_PER_APPCAST (1000) items
  const int max_items_plus_extra = 1100;
  for (int i = 0; i < max_items_plus_extra; i++)
    {
      items += "        <item>\n"
             "            <title>Version " + std::to_string(i) + "</title>\n"
             "            <sparkle:version>" + std::to_string(i) + ".0.0</sparkle:version>\n"
             "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
             "            <enclosure url=\"https://example.com/app-" + std::to_string(i) + ".dmg\" "
             "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
             "length=\"1234\" type=\"application/octet-stream\" />\n"
             "        </item>\n";
    }

  std::string many_items_xml = many_items_start + items + many_items_end;
  auto appcast = reader->load_from_string(many_items_xml);
  EXPECT_NE(appcast, nullptr);
  EXPECT_EQ(appcast->items.size(), 1000); // Should be limited to MAX_ITEMS_PER_APPCAST
}

TEST(AppCastTest, InvalidItemVersion)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string invalid_version =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>invalid.version.format</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_version);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, InvalidShortVersion)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string invalid_short_version =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:shortVersionString>invalid.short.version</sparkle:shortVersionString>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_short_version);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, InvalidItemLink)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string invalid_item_link =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <link>invalid://link</link>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_item_link);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, HttpItemLink)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string http_item_link =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <link>http://example.com/item</link>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(http_item_link);
  EXPECT_NE(appcast, nullptr);
  EXPECT_EQ(appcast->items[0]->link, "http://example.com/item");
}

TEST(AppCastTest, InvalidReleaseNotesLink)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string invalid_release_notes =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>invalid://notes</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_release_notes);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, HttpReleaseNotesLink)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string http_release_notes =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <sparkle:releaseNotesLink>http://example.com/notes</sparkle:releaseNotesLink>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(http_release_notes);
  EXPECT_NE(appcast, nullptr);
  EXPECT_EQ(appcast->items[0]->release_notes_link, "http://example.com/notes");
}

TEST(AppCastTest, CriticalUpdateWithInvalidVersion)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string critical_update_invalid =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <sparkle:criticalUpdate sparkle:version=\"invalid.critical.version\" />\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(critical_update_invalid);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, TooManyEnclosures)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string many_enclosures_start =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n";

  std::string many_enclosures_end =
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  std::string enclosures;
  // Create more than MAX_ENCLOSURES_PER_ITEM (10) enclosures
  const int max_enclosures_plus_extra = 15;
  for (int i = 0; i < max_enclosures_plus_extra; i++)
    {
      enclosures += "            <enclosure url=\"https://example.com/app-" + std::to_string(i) + ".dmg\" "
                  "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
                  "length=\"1234\" type=\"application/octet-stream\" />\n";
    }

  std::string many_enclosures_xml = many_enclosures_start + enclosures + many_enclosures_end;
  auto appcast = reader->load_from_string(many_enclosures_xml);
  EXPECT_NE(appcast, nullptr);
  EXPECT_EQ(appcast->items.size(), 1);
}

TEST(AppCastTest, InvalidEnclosureUrl)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string invalid_enclosure_url =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"invalid://url\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_enclosure_url);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, HttpEnclosureUrl)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string http_enclosure_url =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"http://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(http_enclosure_url);
  EXPECT_NE(appcast, nullptr);
  EXPECT_EQ(appcast->items[0]->enclosure->url, "http://example.com/app-1.0.0.dmg");
}

TEST(AppCastTest, InvalidMimeType)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string invalid_mime_type =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"invalid/mime/type/with/too/many/slashes\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_mime_type);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, SuspiciousFileLength)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  const uint64_t max_file_size = 10ULL * 1024 * 1024 * 1024; // 10GB
  const uint64_t huge_size = max_file_size + 1;              // Exceeds MAX_FILE_SIZE

  std::string suspicious_length =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"" + std::to_string(huge_size) + "\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(suspicious_length);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, WrongSignatureLength)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string wrong_signature_length =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"dGVzdA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(wrong_signature_length);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, FilterRejectsItem)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return false; }); // Filter rejects all items

  std::string valid_appcast =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(valid_appcast);
  EXPECT_NE(appcast, nullptr);
  EXPECT_EQ(appcast->items.size(), 0); // No items should be included due to filter
}

TEST(AppCastTest, EmptyUrlString)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  // Test is_valid_url with empty string
  std::string empty_url_test =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(empty_url_test);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, FtpUrl)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string ftp_url =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"ftp://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(ftp_url);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, EmptyHostUrl)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string empty_host_url =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(empty_host_url);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, EmptyVersion)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string empty_version_test =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version></sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(empty_version_test);
  EXPECT_NE(appcast, nullptr); // Empty version should be allowed
  EXPECT_EQ(appcast->items.size(), 1);
  EXPECT_EQ(appcast->items[0]->version, "");
}

TEST(AppCastTest, InvalidCanaryPercentage)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string invalid_canary_percentage =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\" xmlns:unfold=\"http://unfold.update.org/xml-namespaces/unfold\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <unfold:canary>\n"
    "                <interval>\n"
    "                    <percentage>150</percentage>\n"
    "                    <days>7</days>\n"
    "                </interval>\n"
    "            </unfold:canary>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_canary_percentage);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, InvalidCanaryDays)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string invalid_canary_days =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\" xmlns:unfold=\"http://unfold.update.org/xml-namespaces/unfold\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <unfold:canary>\n"
    "                <interval>\n"
    "                    <percentage>5</percentage>\n"
    "                    <days>-10</days>\n"
    "                </interval>\n"
    "            </unfold:canary>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_canary_days);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, InvalidPhasedPercentage)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  // Test with invalid canary interval that has percentage > 100
  std::string invalid_phased_percentage =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\" xmlns:unfold=\"http://unfold.update.org/xml-namespaces/unfold\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <unfold:canary>\n"
    "                <interval>\n"
    "                    <percentage>200</percentage>\n"
    "                    <days>7</days>\n"
    "                </interval>\n"
    "            </unfold:canary>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_phased_percentage);
  EXPECT_EQ(appcast, nullptr); // Should fail due to invalid percentage > 100
}

TEST(AppCastTest, InvalidPhasedDays)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  // For phased rollouts, the days value is indirectly calculated from phasedRolloutInterval
  // To test invalid days, we need to test with canary rollout intervals
  std::string invalid_phased_days =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\" xmlns:unfold=\"http://unfold.update.org/xml-namespaces/unfold\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <unfold:canary>\n"
    "                <interval>\n"
    "                    <percentage>25</percentage>\n"
    "                    <days>0</days>\n"
    "                </interval>\n"
    "            </unfold:canary>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_phased_days);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, ValidPhasedRollout)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  // Use a larger interval value that will result in at least 1 day per phase
  // With 7 phases, we need at least 86400 seconds (1 day) per phase
  const uint64_t daily_interval = 86400; // 1 day in seconds

  std::string valid_phased_rollout =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <sparkle:phasedRolloutInterval>" + std::to_string(daily_interval) + "</sparkle:phasedRolloutInterval>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(valid_phased_rollout);
  EXPECT_NE(appcast, nullptr);
  EXPECT_EQ(appcast->items.size(), 1);
  // Rollout interval validation should pass
}

TEST(AppCastTest, StringTooLongForSanitize)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  const size_t max_string_length = 1024; // MAX_STRING_LENGTH
  const size_t extra_length = 100;
  std::string long_title(max_string_length + extra_length, 'a');

  std::string long_title_appcast =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>" + long_title + "</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(long_title_appcast);
  EXPECT_NE(appcast, nullptr);                           // String gets sanitized, not rejected
  EXPECT_EQ(appcast->title.length(), max_string_length); // Should be truncated to MAX_STRING_LENGTH
}

TEST(AppCastTest, InvalidBase64Signature)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string invalid_base64_signature =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://example.com/app-1.0.0.dmg\" "
    "sparkle:edSignature=\"invalid!!!base64!!!characters!!!here!!!that!!!cannot!!!be!!!decoded!!!\" "
    "length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(invalid_base64_signature);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, MissingEnclosureForItem)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string no_enclosure_test =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <description>Test updates</description>\n"
    "        <language>en</language>\n"
    "        <link>https://example.com/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "        </item>\n"
    "    </channel>\n"
    "</rss>\n";

  auto appcast = reader->load_from_string(no_enclosure_test);
  EXPECT_NE(appcast, nullptr);         // Should succeed but have no items
  EXPECT_EQ(appcast->items.size(), 0); // Item is filtered out due to missing enclosure
}

TEST(AppCastTest, XMLDSigVerificationDisabledByDefault)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  std::string appcast_with_signature =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
    "    <channel>\n"
    "        <title>Workrave Test Appcast</title>\n"
    "        <description>Most recent updates to Workrave Test</description>\n"
    "        <language>en</language>\n"
    "        <link>https://workrave.org/</link>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <link>https://workrave.org</link>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <pubDate>Sun, 17 Apr 2022 19:30:14 +0200</pubDate>\n"
    "            <enclosure url=\"https://localhost:1337/v2.zip\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "    <ds:Signature>\n"
    "        <ds:SignedInfo>\n"
    "            <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"
    "            <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n"
    "            <ds:Reference URI=\"#channel\">\n"
    "                <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n"
    "                <ds:DigestValue>test-digest-value</ds:DigestValue>\n"
    "            </ds:Reference>\n"
    "        </ds:SignedInfo>\n"
    "        <ds:SignatureValue>test-signature-value</ds:SignatureValue>\n"
    "        <ds:KeyInfo>\n"
    "            <ds:X509Data>\n"
    "                <ds:X509Certificate>test-certificate</ds:X509Certificate>\n"
    "            </ds:X509Data>\n"
    "        </ds:KeyInfo>\n"
    "    </ds:Signature>\n"
    "</rss>\n";

  // Should succeed even with signature present when verification is disabled
  auto appcast = reader->load_from_string(appcast_with_signature);
  EXPECT_NE(appcast, nullptr);
  EXPECT_EQ(appcast->items.size(), 1);
}

// Generate ECDSA keys
// ECDSA key generation and signing commands:
// openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem
// openssl ec -in ec_private.pem -pubout -out ec_public.pem
// xmlsec1 sign --privkey-pem:unfold ec_private.pem --output appcast-signed.xml appcast-signed-in.xml

TEST(AppCastTest, XMLDSigHasSignatureDetection)
{
  std::string appcast_without_signature =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "    </channel>\n"
    "</rss>\n";

  std::string appcast_with_signature =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "    </channel>\n"
    "    <ds:Signature>\n"
    "        <ds:SignedInfo>\n"
    "            <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n"
    "        </ds:SignedInfo>\n"
    "    </ds:Signature>\n"
    "</rss>\n";

  EXPECT_FALSE(unfold::crypto::XMLDSigVerifier::has_signature(appcast_without_signature));
  EXPECT_TRUE(unfold::crypto::XMLDSigVerifier::has_signature(appcast_with_signature));
}

TEST(AppCastTest, XMLDSigVerificationWithoutTrustedKey)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  reader->set_xmldsig_verification_enabled(true);

  std::string appcast_with_signature =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
    "    <channel>\n"
    "        <title>Test Appcast</title>\n"
    "        <item>\n"
    "            <title>Version 1.0</title>\n"
    "            <sparkle:version>1.0.0</sparkle:version>\n"
    "            <enclosure url=\"https://example.com/app.zip\" sparkle:edSignature=\"aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==\" length=\"1234\" type=\"application/octet-stream\" />\n"
    "        </item>\n"
    "    </channel>\n"
    "    <ds:Signature>\n"
    "        <ds:SignedInfo>\n"
    "            <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n"
    "        </ds:SignedInfo>\n"
    "    </ds:Signature>\n"
    "</rss>\n";

  // Should fail when verification is enabled but no trusted key is set
  auto appcast = reader->load_from_string(appcast_with_signature);
  EXPECT_EQ(appcast, nullptr);
}

TEST(AppCastTest, XMLDSigCertificateAddResult)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  // Test adding an invalid certificate
  auto result = reader->add_xmldsig_public_key("", "");
  EXPECT_FALSE(result.has_value());
  EXPECT_TRUE(result.has_error());

  // Test adding a valid certificate (mock PEM format)
  std::string valid_cert_pem =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7ABCDEF...\n"
    "-----END CERTIFICATE-----\n";

  // This will fail because it's not a real certificate, but should return a proper error
  auto result2 = reader->add_xmldsig_public_key("", valid_cert_pem);
  EXPECT_FALSE(result2.has_value());
  EXPECT_TRUE(result2.has_error());
}

TEST(AppCastTest, XMLDSigPublicKeyAddResult)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  // Test adding an invalid public key
  auto result = reader->add_xmldsig_public_key("", "");
  EXPECT_FALSE(result.has_value());
  EXPECT_TRUE(result.has_error());

  // Test adding a valid public key (mock PEM format)
  std::string valid_key_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7ABCDEF...\n"
    "-----END PUBLIC KEY-----\n";

  // This will fail because it's not a real key, but should return a proper error
  auto result2 = reader->add_xmldsig_public_key("unfold", valid_key_pem);
  EXPECT_FALSE(result2.has_value());
  EXPECT_TRUE(result2.has_error());
}

TEST(AppCastTest, XMLDSigECDSAKeyTests)
{
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });

  // Load ECDSA public key from test data
  // Generated with: openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem && openssl ec -in ec_private.pem -pubout
  // -out ec_public.pem
  std::ifstream ec_pub_file("ec_public.pem");
  ASSERT_TRUE(ec_pub_file.is_open()) << "Failed to open test/data/ec_public.pem";

  std::string ecdsa_public_key((std::istreambuf_iterator<char>(ec_pub_file)), std::istreambuf_iterator<char>());
  ec_pub_file.close();

  // Test adding ECDSA public key - should succeed with modern XMLSec
  auto result = reader->add_xmldsig_public_key("unfold", ecdsa_public_key);
  EXPECT_TRUE(result.has_value());
  EXPECT_FALSE(result.has_error());

  if (result.has_value())
    {
      std::cout << "ECDSA P-256 key successfully added to XMLSec key manager" << std::endl;
    }
  else
    {
      std::cout << "ECDSA key failed to add: " << result.error().message() << std::endl;
      FAIL() << "ECDSA should be supported in XMLSec 1.3.7 with OpenSSL backend";
    }
}

TEST(AppCastTest, XMLDSigVerifierDirectAPI)
{
  // Test XMLDSigVerifier API directly with ECDSA key from test data
  auto verifier_result = unfold::crypto::XMLDSigVerifier::create();
  EXPECT_TRUE(verifier_result.has_value());

  if (verifier_result.has_value())
    {
      auto verifier = std::move(verifier_result.value());

      // Load ECDSA public key from test data files
      std::ifstream ec_pub_file("ec_public.pem");
      ASSERT_TRUE(ec_pub_file.is_open()) << "Failed to open test/data/ec_public.pem";

      std::string ecdsa_public_key((std::istreambuf_iterator<char>(ec_pub_file)), std::istreambuf_iterator<char>());
      ec_pub_file.close();

      auto add_result = verifier.add_trusted_public_key("unfold", ecdsa_public_key);
      EXPECT_TRUE(add_result.has_value()) << "ECDSA key should be supported in XMLSec 1.3.7";

      if (add_result.has_value())
        {
          std::cout << "ECDSA P-256 key successfully added to XMLDSigVerifier!" << std::endl;
        }
      else
        {
          FAIL() << "Failed to add ECDSA key: " << add_result.error().message();
        }

      // Test signature detection on various XML formats
      std::string xml_with_ecdsa_signature =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<rss version=\"2.0\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
        "    <channel><title>Test</title></channel>\n"
        "    <ds:Signature>\n"
        "        <ds:SignedInfo>\n"
        "            <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256\"/>\n"
        "        </ds:SignedInfo>\n"
        "    </ds:Signature>\n"
        "</rss>\n";

      EXPECT_TRUE(verifier.has_signature(xml_with_ecdsa_signature));

      // Test clearing keys
      auto clear_result = verifier.clear_trusted_keys();
      EXPECT_TRUE(clear_result.has_value());
      EXPECT_FALSE(clear_result.has_error());
    }
}

TEST(AppCastTest, XMLDSigVerificationWithECDSASignedFile)
{
  // Test verification of the actual signed XML file with ECDSA
  auto reader = std::make_shared<AppcastReader>([](auto item) { return true; });
  reader->set_xmldsig_verification_enabled(true);

  // Add the ECDSA public key that corresponds to the private key used to sign appcast-signed.xml
  std::ifstream ec_pub_file("ec_public.pem");
  if (!ec_pub_file.is_open())
    {
      FAIL() << "Failed to open ec_public.pem";
    }

  std::string ecdsa_public_key((std::istreambuf_iterator<char>(ec_pub_file)), std::istreambuf_iterator<char>());
  ec_pub_file.close();

  auto add_key_result = reader->add_xmldsig_public_key("unfold", ecdsa_public_key);

  if (!add_key_result.has_value())
    {
      // ECDSA should be supported in XMLSec 1.3.7 with OpenSSL backend
      FAIL() << "ECDSA not supported: " << add_key_result.error().message();
    }

  // Load the signed XML file
  auto appcast = reader->load_from_file("appcast-signed.xml");

  if (!appcast)
    {
      FAIL() << "Could not load appcast-signed.xml - file may not exist or verification failed";
    }

  // Verify the appcast was loaded successfully
  EXPECT_NE(appcast, nullptr);
  EXPECT_FALSE(appcast->items.empty());

  // Verify basic appcast properties
  EXPECT_EQ(appcast->title, "Workrave");
  EXPECT_EQ(appcast->description, "Workrave");
  EXPECT_EQ(appcast->language, "en");
  EXPECT_EQ(appcast->link, "https://workrave.org/");

  // Check that we have multiple items (since it's a comprehensive test file)
  EXPECT_GT(appcast->items.size(), 1);

  std::cout << "Successfully loaded and verified ECDSA-signed appcast with " << appcast->items.size() << " items" << std::endl;
}

TEST(AppCastTest, XMLDSigECDSASignatureInfoExtraction)
{
  auto verifier_result = unfold::crypto::XMLDSigVerifier::create();
  EXPECT_TRUE(verifier_result.has_value());

  if (verifier_result.has_value())
    {
      auto verifier = std::move(verifier_result.value());

      // Test signature info extraction from ECDSA signed document
      std::string ecdsa_signed_xml =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<rss version=\"2.0\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
        "    <channel>\n"
        "        <title>Test Appcast</title>\n"
        "        <item>\n"
        "            <title>Version 1.0.0</title>\n"
        "        </item>\n"
        "    </channel>\n"
        "    <ds:Signature Id=\"ecdsa-signature\">\n"
        "        <ds:SignedInfo>\n"
        "            <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"
        "            <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256\"/>\n"
        "            <ds:Reference URI=\"\">\n"
        "                <ds:Transforms>\n"
        "                    <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n"
        "                    <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"
        "                </ds:Transforms>\n"
        "                <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n"
        "                <ds:DigestValue>ecdsa-sample-digest-value</ds:DigestValue>\n"
        "            </ds:Reference>\n"
        "        </ds:SignedInfo>\n"
        "        <ds:SignatureValue>ecdsa-sample-signature-value</ds:SignatureValue>\n"
        "        <ds:KeyInfo>\n"
        "            <ds:KeyName>unfold</ds:KeyName>\n"
        "        </ds:KeyInfo>\n"
        "    </ds:Signature>\n"
        "</rss>\n";

      auto info_result = verifier.get_signature_info(ecdsa_signed_xml);
      EXPECT_TRUE(info_result.has_value());

      if (info_result.has_value())
        {
          auto info = info_result.value();
          EXPECT_EQ(info.signature_id, "ecdsa-signature");
          EXPECT_EQ(info.signature_method, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
          EXPECT_EQ(info.canonicalization_method, "http://www.w3.org/2001/10/xml-exc-c14n#");
          EXPECT_EQ(info.digest_method, "http://www.w3.org/2001/04/xmlenc#sha256");
          EXPECT_FALSE(info.has_x509_certificate); // Using KeyName instead of X509Data

          // Test that we can detect the ECDSA signature method
          EXPECT_TRUE(info.signature_method.find("ecdsa") != std::string::npos);
        }
    }
}

TEST(AppCastTest, XMLDSigRealSignedFileInfo)
{
  // Test signature info extraction from the actual signed file
  auto verifier_result = unfold::crypto::XMLDSigVerifier::create();
  EXPECT_TRUE(verifier_result.has_value());

  if (verifier_result.has_value())
    {
      auto verifier = std::move(verifier_result.value());

      // Read the actual signed XML file
      std::ifstream file("appcast-signed.xml");
      if (!file.is_open())
        {
          FAIL() << "appcast-signed.xml not found";
        }

      std::string signed_xml_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
      file.close();

      // Test that we can detect the signature
      EXPECT_TRUE(verifier.has_signature(signed_xml_content));

      // Extract signature info
      auto info_result = verifier.get_signature_info(signed_xml_content);
      EXPECT_TRUE(info_result.has_value());

      if (info_result.has_value())
        {
          auto info = info_result.value();

          // Verify this is an ECDSA signature
          EXPECT_EQ(info.signature_method, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
          EXPECT_EQ(info.canonicalization_method, "http://www.w3.org/2001/10/xml-exc-c14n#");
          EXPECT_EQ(info.digest_method, "http://www.w3.org/2001/04/xmlenc#sha256");

          // Should use KeyName "unfold" not X509 certificate
          EXPECT_FALSE(info.has_x509_certificate);

          std::cout << "Real signed file signature method: " << info.signature_method << std::endl;
          std::cout << "Canonicalization method: " << info.canonicalization_method << std::endl;
          std::cout << "Digest method: " << info.digest_method << std::endl;
        }
    }
}
