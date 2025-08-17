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

#include "UpgradeChecker.hh"

#include <exception>
#include <memory>
#include <utility>
#include <boost/outcome/try.hpp>
#include <boost/process.hpp>
#include <boost/url/url.hpp>
#include <fmt/os.h>
#include <fmt/std.h>
#include <spdlog/fmt/ostr.h>

#include "Platform.hh"
#include "UnfoldErrors.hh"
#include "utils/DateUtils.hh"

UpgradeChecker::UpgradeChecker(std::shared_ptr<Platform> platform,
                               std::shared_ptr<unfold::http::HttpClient> http,
                               std::shared_ptr<SigstoreVerifier> sigstore_verifier,
                               std::shared_ptr<Hooks> hooks)
  : platform(std::move(platform))
  , http(std::move(http))
  , sigstore_verifier(std::move(sigstore_verifier))
  , hooks(hooks)
  , appcast_reader(std::make_shared<AppcastReader>([this](auto item) { return is_applicable(item); }))
{
}

outcome::std_result<void>
UpgradeChecker::set_appcast(const std::string &url)
{
  appcast_url = url;
  sigstore_url = url + ".sigstore";
  return outcome::success();
}

outcome::std_result<void>
UpgradeChecker::set_current_version(const std::string &version)
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

outcome::std_result<void>
UpgradeChecker::set_allowed_channels(const std::vector<std::string> &channels)
{
  allowed_channels = channels;
  return outcome::success();
}

void
UpgradeChecker::set_pre_download_validation_callback(unfold::Unfold::pre_download_validation_callback_t callback)
{
  update_validation_callback = callback;
}

std::shared_ptr<unfold::UpdateInfo>
UpgradeChecker::get_update_info() const
{
  return update_info;
}

std::shared_ptr<AppcastItem>
UpgradeChecker::get_selected_update() const
{
  return selected_item;
}

std::chrono::seconds
UpgradeChecker::get_rollout_delay_for_priority(int priority) const
{
  if (selected_item == nullptr)
    {
      return std::chrono::seconds(0);
    }

  auto it = std::find_if(selected_item->canary_rollout_intervals.rbegin(),
                         selected_item->canary_rollout_intervals.rend(),
                         [priority](const auto &interval) { return priority > interval.second; });

  if (it != selected_item->canary_rollout_intervals.rend())
    {
      return it->first;
    }

  return std::chrono::seconds(0);
}

std::chrono::system_clock::time_point
UpgradeChecker::get_earliest_rollout_time_for_priority(int priority) const
{
  if (selected_item == nullptr)
    {
      return std::chrono::system_clock::from_time_t(0);
    }

  auto delay = get_rollout_delay_for_priority(priority);
  auto pub_date = unfold::utils::DateUtils::parse_time_point(selected_item->publication_date);

  return pub_date + delay;
}

boost::asio::awaitable<outcome::std_result<bool>>
UpgradeChecker::check_for_update()
{
  selected_item.reset();
  update_info.reset();

  auto content = co_await download_appcast();
  if (!content)
    {
      co_return content.as_failure();
    }

  auto sigstore_content = co_await sigstore_verifier->verify(sigstore_url, content.value());
  if (!sigstore_content)
    {
      co_return sigstore_content.as_failure();
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

      // Validate update if callback is set
      if (update_validation_callback && update_info)
        {
          logger->info("update available, validating update");

          auto validation_result = update_validation_callback(*update_info);
          if (!validation_result)
            {
              logger->error("update validation failed: {}", validation_result.error().message());
              selected_item.reset();
              update_info.reset();
              co_return validation_result.as_failure();
            }
          if (!validation_result.value())
            {
              logger->warn("update to version {} rejected by validation callback", update_info->version);
              selected_item.reset();
              update_info.reset();
              co_return false;
            }
          logger->info("update to version {} validated successfully", update_info->version);
        }

      co_return true;
    }

  co_return false;
}

boost::asio::awaitable<outcome::std_result<std::string>>
UpgradeChecker::download_appcast()
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
UpgradeChecker::parse_appcast(const std::string &appcast_xml)
{
  auto appcast = appcast_reader->load_from_string(appcast_xml);
  if (!appcast)
    {
      logger->info("failed to parse appcast");
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
UpgradeChecker::is_applicable(std::shared_ptr<AppcastItem> item)
{
  if (!platform->is_supported_os(item->enclosure->os))
    {
      return false;
    }

  if (!item->minimum_system_version.empty() && platform->is_supported_os_version(item->minimum_system_version))
    {
      return false;
    }

  if (!item->channel.empty() && !allowed_channels.empty()
      && std::find(allowed_channels.begin(), allowed_channels.end(), item->channel) == allowed_channels.end())
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
UpgradeChecker::build_update_info(std::shared_ptr<Appcast> appcast)
{
  update_info = std::make_shared<unfold::UpdateInfo>();

  auto items = appcast->items;

  if (!items.empty())
    {
      selected_item = items.front();

      update_info->title = appcast->title;
      update_info->version = selected_item->version;
      update_info->current_version = current_version_str;
      update_info->download_url = selected_item->enclosure ? selected_item->enclosure->url : "";

      for (auto x: items)
        {
          spdlog::info("applicable {}", x->version);

          auto r = unfold::UpdateReleaseNotes{.version = x->version, .date = x->publication_date, .markdown = x->description};
          update_info->release_notes.push_back(r);
        }
    }
}

#ifdef UNFOLD_WITH_XMLSEC

outcome::std_result<void>
UpgradeChecker::add_xmldsig_public_key(const std::string &key_name, const std::string &public_key_pem)
{
  return appcast_reader->add_xmldsig_public_key(key_name, public_key_pem);
}

void
UpgradeChecker::clear_xmldsig_trusted_keys()
{
  appcast_reader->clear_xmldsig_trusted_keys();
}

void
UpgradeChecker::set_xmldsig_verification_enabled(bool enabled)
{
  appcast_reader->set_xmldsig_verification_enabled(enabled);
}

#endif
