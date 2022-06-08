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

#include "Checker.hh"

#include <exception>
#include <memory>
#include <system_error>
#include <utility>
#include <fstream>
#include <spdlog/fmt/ostr.h>

#include <boost/outcome/try.hpp>
#include <boost/url/url.hpp>
#include <boost/process.hpp>

#include "UnfoldErrors.hh"
#include "crypto/SignatureVerifier.hh"
#include "utils/TempDirectory.hh"

#include "Platform.hh"

Checker::Checker(std::shared_ptr<Platform> platform, std::shared_ptr<unfold::http::HttpClient> http, std::shared_ptr<Hooks> hooks)
  : platform(std::move(platform))
  , http(std::move(http))
  , hooks(hooks)
{
}

outcome::std_result<void>
Checker::set_appcast(const std::string &url)
{
  appcast_url = url;
  return outcome::success();
}

outcome::std_result<void>
Checker::set_current_version(const std::string &version)
{
  try
    {
      current_version_str = version;
      current_version.from_string(version);
    }
  catch (std::exception &e)
    {
      logger->error("invalid current version '{}' ({})", version, e.what());
      return outcome::failure(unfold::UnfoldErrc::InvalidArgument);
    }
  return outcome::success();
}

std::shared_ptr<unfold::UpdateInfo>
Checker::get_update_info() const
{
  return update_info;
}

std::shared_ptr<AppcastItem>
Checker::get_selected_update() const
{
  return selected_item;
}

boost::asio::awaitable<outcome::std_result<bool>>
Checker::check_for_updates()
{
  selected_item.reset();
  update_info.reset();

  auto content = co_await download_appcast();
  if (!content)
    {
      co_return content.as_failure();
    }

  auto appcast = parse_appcast(content.value());
  if (!appcast)
    {
      co_return appcast.as_failure();
    }

  auto items = appcast.value()->items;

  if (!items.empty())
    {
      build_update_info(appcast.value());
      co_return true;
    }

  co_return false;
}

boost::asio::awaitable<outcome::std_result<std::string>>
Checker::download_appcast()
{
  auto rc = co_await http->get(appcast_url);

  if (!rc)
    {
      logger->info("failed to download appcast ({})", rc.error());
      co_return unfold::UnfoldErrc::AppcastDownloadFailed;
    }

  auto [result, content] = rc.value();
  if (result != 200)
    {
      logger->info("failed to download appcast ({} {})", result, content);
      co_return unfold::UnfoldErrc::AppcastDownloadFailed;
    }

  if (content.empty())
    {
      logger->info("failed to download appcast (empty)");
      co_return unfold::UnfoldErrc::InvalidAppcast;
    }

  co_return content;
}

outcome::std_result<std::shared_ptr<Appcast>>
Checker::parse_appcast(const std::string &appcast_xml)
{
  AppcastReader reader([this](auto item) { return is_applicable(item); });

  auto appcast = reader.load_from_string(appcast_xml);
  if (!appcast)
    {
      return unfold::UnfoldErrc::InvalidAppcast;
    }

  auto items = appcast->items;
  std::sort(items.begin(), items.end(), [&](auto a, auto b) -> bool {
    semver::version versiona;
    auto rca = versiona.from_string_noexcept(a->version);
    semver::version versionb;
    auto rcb = versionb.from_string_noexcept(b->version);
    return rca && rcb && a < b;
  });

  return appcast;
}

bool
Checker::is_applicable(std::shared_ptr<AppcastItem> item)
{
  if (!platform->is_supported_os(item->enclosure->os))
    {
      return false;
    }

  if (!item->minimum_system_version.empty() && platform->is_supported_os_version(item->minimum_system_version))
    {
      return false;
    }

  // TODO: custom version comparator
  semver::version version;
  bool version_ok = version.from_string_noexcept(item->version);
  if (!version_ok)
    {
      return false;
    }

  if (version <= current_version)
    {
      return false;
    }

  return true;
}

void
Checker::build_update_info(std::shared_ptr<Appcast> appcast)
{
  update_info = std::make_shared<unfold::UpdateInfo>();

  auto items = appcast->items;

  if (!items.empty())
    {
      selected_item = items.front();

      update_info->title = appcast->title;
      update_info->version = selected_item->version;
      update_info->current_version = current_version_str;

      for (auto x: items)
        {
          spdlog::info("applicable {}", x->version);
          auto r = unfold::UpdateReleaseNotes{x->version, x->publication_date, x->description};
          update_info->release_notes.push_back(r);
        }
    }
}
