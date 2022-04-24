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

#include "SignatureVerifierErrors.hh"
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <memory>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#if SPDLOG_VERSION >= 10600
#  include <spdlog/pattern_formatter.h>
#endif
#if SPDLOG_VERSION >= 10801
#  include <spdlog/cfg/env.h>
#endif

#include "AppCast.hh"
#include "HTTPClient.hh"
#include "HTTPServer.hh"
#include "Logging.hh"
#include "SignatureVerifier.hh"

#define BOOST_TEST_MODULE "unfold"
#include <boost/test/unit_test.hpp>

namespace
{
  // openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 10000 -out cert.pem -subj "/CN=localhost"
  std::string const cert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICpDCCAYwCCQDU+pQ3ZUD30jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n"
    "b2NhbGhvc3QwHhcNMjIwNDE3MjE0MjMzWhcNNDkwOTAyMjE0MjMzWjAUMRIwEAYD\n"
    "VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDV\n"
    "r4sAS/gBsfurDLk6A9O+cZnaSH4zWvOXXmGRHSjgAQYMyVZ9sLVXn9Odmj+h6Qg0\n"
    "XMY4AzO/gATqF2voW1CtlPIcSa7eJPki3TD/UUn3ToYn11rfSaXjYB41FBCubp5y\n"
    "4S5Fg2GsWM1/5GYfLixzK2rM+DirEc05xjAqUWMtKFDXyD1O6KfOoeaq5qw5EojR\n"
    "9Ziu4K29cS6c9tze1Q4AXtVDdzNTypaC0RD+orNsZPQqIAfDfnAhwaJcsRlnGGf5\n"
    "iGe0jqJ+lThKsPO3x66nga66IqW1qe6OOs9MLAkZN92mXhS77qQeumi1hIYmUn3S\n"
    "EkydgQOzJTnlgmb8D9P1AgMBAAEwDQYJKoZIhvcNAQELBQADggEBADBotTUWDZTM\n"
    "aY/NX7/CkE2CnEP18Ccbv21edY+0UBy7L4lWBtLcvHZJ1HaFq4T4FfwvD+nNbRVM\n"
    "Up8j6rCFMKr/4tsD0UcKdBphDESpk0lq7uKPF3H2sU4sEnzQ/YI/IIT1gcp8iJLZ\n"
    "O+i0ur4CaTmPXF7oJXmAb0sIvUTQe+FXNvb4urqJ97Bu09vLmRkUvqmtELj1hDtf\n"
    "6vGcoQe5C/YsLNkcH1bvntxBT4bW7k47JSbPVKC7JHv2Z4u1Gj6TeQ6wUKRdjWtl\n"
    "Loe2vQ1h9EN6DxhmR7/Nc0sEKaYoJUbbufH+TcdzBqofOOZCBVNQNcQJyqvNpIs0\n"
    "KNdZa9scQjs=\n"
    "-----END CERTIFICATE-----\n";
} // namespace

struct GlobalFixture
{
  GlobalFixture() = default;
  ~GlobalFixture() = default;

  GlobalFixture(const GlobalFixture &) = delete;
  GlobalFixture &operator=(const GlobalFixture &) = delete;
  GlobalFixture(GlobalFixture &&) = delete;
  GlobalFixture &operator=(GlobalFixture &&) = delete;

  void setup()
  {
    const auto *log_file = "unfold-test.log";

    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file, false);
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    auto logger{std::make_shared<spdlog::logger>("unfold", std::initializer_list<spdlog::sink_ptr>{file_sink, console_sink})};
    logger->flush_on(spdlog::level::critical);
    spdlog::set_default_logger(logger);

    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%-5l%$] %v");

#if SPDLOG_VERSION >= 10801
    spdlog::cfg::load_env_levels();
#endif
  }

private:
};

struct Fixture
{
  Fixture() = default;
  ~Fixture() = default;

  Fixture(const Fixture &) = delete;
  Fixture &operator=(const Fixture &) = delete;
  Fixture(Fixture &&) = delete;
  Fixture &operator=(Fixture &&) = delete;

private:
  std::shared_ptr<spdlog::logger> logger{Logging::create("test")};
};

BOOST_TEST_GLOBAL_FIXTURE(GlobalFixture);

BOOST_FIXTURE_TEST_SUITE(s, Fixture)

BOOST_AUTO_TEST_CASE(appcast_load_from_string)
{
  auto reader = std::make_shared<AppcastReader>();

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
}

BOOST_AUTO_TEST_CASE(appcast_load_from_file)
{
  auto reader = std::make_shared<AppcastReader>();

  auto appcast = reader->load_from_file("testappcast.xml");

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
  auto reader = std::make_shared<AppcastReader>();

  std::string appcast_str = "Foo\n";

  auto appcast = reader->load_from_string(appcast_str);
  BOOST_CHECK_EQUAL(appcast.get(), nullptr);
}

BOOST_AUTO_TEST_CASE(appcast_load_invalid_from_file)
{
  auto reader = std::make_shared<AppcastReader>();

  auto appcast = reader->load_from_file("invalidappcast.xml");
  BOOST_CHECK_EQUAL(appcast.get(), nullptr);
}

BOOST_AUTO_TEST_CASE(http_client_get)
{
  HTTPServer server;
  server.add("/foo", "foo\n");
  server.run();

  HTTPClient d;
  d.add_ca_cert(cert);
  auto [result, body] = d.get("https://localhost:1337/foo");

  BOOST_CHECK_EQUAL(result, 200);
  BOOST_CHECK_EQUAL(body, "foo\n");

  server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_get_not_found)
{
  HTTPServer server;
  server.add("/foo", "foo\n");
  server.run();

  HTTPClient d;
  d.add_ca_cert(cert);
  auto [result, body] = d.get("https://localhost:1337/bar");

  BOOST_CHECK_EQUAL(result, 404);
  BOOST_CHECK_EQUAL(body, "The resource '/bar' was not found.");

  server.stop();
}

// TODO: properly report HTTPClient errors
// BOOST_AUTO_TEST_CASE(http_client_not_reachable)
// {
//   HTTPServer server;
//   server.add("/foo", "foo\n");
//   server.run();
//   server.stop();

//   HTTPClient d;
//   d.add_ca_cert(cert);
//   auto [result, body] = d.get("https://localhost:1337/bar");

//   BOOST_CHECK_EQUAL(result, 404);
//   BOOST_CHECK_EQUAL(body, "The resource '/bar' was not found.");
// }

// BOOST_AUTO_TEST_CASE(http_client_host_not_found)
// {
//   HTTPClient d;
//   d.add_ca_cert(cert);
//   auto [result, body] = d.get("https://does-not-exist:1337/bar");

//   BOOST_CHECK_EQUAL(result, 404);
//   BOOST_CHECK_EQUAL(body, "The resource '/bar' was not found.");
// }

// BOOST_AUTO_TEST_CASE(http_client_invalid_url)
// {
//   HTTPClient d;
//   d.add_ca_cert(cert);
//   auto [result, body] = d.get("https://does-not-exist:1337:/bar");

//   BOOST_CHECK_EQUAL(result, 404);
//   BOOST_CHECK_EQUAL(body, "The resource '/bar' was not found.");
// }

BOOST_AUTO_TEST_CASE(http_client_download_file)
{
  HTTPServer server;

  std::string body(10000, 'x');

  server.add("/foo", body);
  server.run();

  HTTPClient d;
  d.add_ca_cert(cert);

  double previous_progress = 0.0;
  auto [result, patload] = d.download("https://localhost:1337/foo", "foo.txt", [&](double progress) {
    BOOST_CHECK_GE(progress, previous_progress);
    previous_progress = progress;
  });

  BOOST_CHECK_EQUAL(result, 200);
  BOOST_CHECK_GE(previous_progress + 0.0001, 1.0);

  server.stop();
}

BOOST_AUTO_TEST_CASE(http_client_download_file_not_found)
{
  HTTPServer server;

  std::string body(10000, 'x');

  server.add("/foo", body);
  server.run();

  HTTPClient d;
  d.add_ca_cert(cert);

  double previous_progress = 0.0;
  auto [result, payload] = d.download("https://localhost:1337/bar", "foo.txt", [&](double progress) {
    BOOST_CHECK_GE(progress, previous_progress);
    previous_progress = progress;
  });

  BOOST_CHECK_EQUAL(result, 404);
  BOOST_CHECK_LE(previous_progress, 0.0001);

  server.stop();
}

BOOST_AUTO_TEST_CASE(signature_verify_file_ok_pem)
{
  // openssl genpkey -algorithm Ed25519 -out ed25519key.pem
  // openssl pkey -in ed25519key.pem -pubout >ed25519pub.pem
  // openssl pkeyutl -sign -inkey ed25519key.pem -out junk.ed25519 -rawin -in junk
  // openssl pkeyutl -verify -pubin -inkey ed25519pub.pem  -rawin -in junk -sigfile junk.ed25519
  // openssl pkey -in ../../test/data/ed25519key.pem -pubout

  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";
  std::string pub_key =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=\n"
    "-----END PUBLIC KEY-----\n";

  SignatureVerifier verifier(unfold::SignatureAlgorithmType::ECDSA, pub_key);
  auto result = verifier.verify("junk", signature);
  BOOST_CHECK_EQUAL(result.error(), SignatureVerifierErrc::Success);
}

BOOST_AUTO_TEST_CASE(signature_verify_file_ok_der)
{
  // openssl genpkey -algorithm Ed25519 -out ed25519key.pem
  // openssl pkey -in ed25519key.pem -pubout >ed25519pub.pem
  // openssl pkeyutl -sign -inkey ed25519key.pem -out junk.ed25519 -rawin -in junk
  // openssl pkeyutl -verify -pubin -inkey ed25519pub.pem  -rawin -in junk -sigfile junk.ed25519
  // openssl pkey -in ../../test/data/ed25519key.pem -pubout -outform DER | base64

  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";
  std::string pub_key = "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=";

  SignatureVerifier verifier(unfold::SignatureAlgorithmType::ECDSA, pub_key);
  auto result = verifier.verify("junk", signature);
  BOOST_CHECK_EQUAL(result.error(), SignatureVerifierErrc::Success);
}

BOOST_AUTO_TEST_CASE(signature_verify_invalid_pubkey)
{
  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";
  std::string pub_key = "foo";

  SignatureVerifier verifier(unfold::SignatureAlgorithmType::ECDSA, pub_key);
  auto result = verifier.verify("junk", signature);
  BOOST_CHECK_EQUAL(result.error(), SignatureVerifierErrc::InvalidPublicKey);
}

BOOST_AUTO_TEST_CASE(signature_verify_invalid_signature)
{
  std::string signature;
  std::string pub_key = "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=";

  SignatureVerifier verifier(unfold::SignatureAlgorithmType::ECDSA, pub_key);
  auto result = verifier.verify("junk", signature);
  BOOST_CHECK_EQUAL(result.error(), SignatureVerifierErrc::InvalidSignature);
}

BOOST_AUTO_TEST_CASE(signature_verify_file_nok)
{
  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";
  std::string pub_key =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=\n"
    "-----END PUBLIC KEY-----\n";

  SignatureVerifier verifier(unfold::SignatureAlgorithmType::ECDSA, pub_key);
  auto result = verifier.verify("morejunk", signature);
  BOOST_CHECK_EQUAL(result.error(), SignatureVerifierErrc::Mismatch);
}

BOOST_AUTO_TEST_CASE(signature_verify_file_not_found)
{
  std::string signature = "aagGLGqLIRVHOBPn+dwXmkJTp6fg2BOGX7v29ZsKPBE/6wTqFpwMqQpuXBrK0hrzZdx5TjMUvfEEHUvUmQW5BA==";
  std::string pub_key =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=\n"
    "-----END PUBLIC KEY-----\n";

  SignatureVerifier verifier(unfold::SignatureAlgorithmType::ECDSA, pub_key);
  auto result = verifier.verify("notfound", signature);
  BOOST_CHECK_EQUAL(result.error(), SignatureVerifierErrc::NotFound);
}

BOOST_AUTO_TEST_SUITE_END()
