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

#include "unfold/Unfold.hh"
#include "unfold/UnfoldErrors.hh"
#include "http/HttpServer.hh"

#include "Fixture.hpp"
#include "TestPlatform.hh"
#include "UpgradeControl.hh"

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

BOOST_FIXTURE_TEST_SUITE(unfold_upgrade_control_test, Fixture)

BOOST_AUTO_TEST_CASE(upgrade_invalid_key)
{
  unfold::utils::IOContext io_context{1};
  UpgradeControl control(std::make_shared<TestPlatform>(), io_context);

  auto rc = control.set_signature_verification_key("xxxxMCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=xxx");
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InvalidArgument);
}

BOOST_AUTO_TEST_CASE(upgrade_invalid_cert)
{
  unfold::utils::IOContext io_context{1};
  UpgradeControl control(std::make_shared<TestPlatform>(), io_context);

  auto rc = control.set_certificate("cert");
  BOOST_CHECK_EQUAL(rc.has_error(), true);
  BOOST_CHECK_EQUAL(rc.error(), unfold::UnfoldErrc::InvalidArgument);
}

BOOST_AUTO_TEST_CASE(upgrade_control_check)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.add_file("/workrave-1.11.0-alpha.1.exe", "junk");
  server.add_file("/installer.sh", "installer.sh");
  server.run();

  unfold::utils::IOContext io_context{1};
  UpgradeControl control(std::make_shared<TestPlatform>(), io_context);

  auto rc = control.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_certificate(cert);
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_signature_verification_key("MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_current_version("1.10.45");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> {
      try
        {
          auto rc = co_await control.check_for_updates();
          BOOST_CHECK_EQUAL(rc.has_error(), false);

          // TODO: fails on Wndows
          // auto ri = co_await control.install();
          // BOOST_CHECK_EQUAL(ri.has_error(), false);
        }
      catch (std::exception &e)
        {
          spdlog::info("Exception {}", e.what());
          BOOST_CHECK(false);
        }
    },
    boost::asio::detached);
  ioc.run();

  server.stop();
}

BOOST_AUTO_TEST_CASE(upgrade_control_periodic_check)
{
  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "appcast.xml");
  server.add_file("/workrave-1.11.0-alpha.1.exe", "junk");
  server.add_file("/installer.sh", "installer.sh");
  server.run();

  unfold::utils::IOContext io_context{1};
  UpgradeControl control(std::make_shared<TestPlatform>(), io_context);

  auto rc = control.set_appcast("https://127.0.0.1:1337/appcast.xml");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_certificate(cert);
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_signature_verification_key("MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  rc = control.set_current_version("1.10.45");
  BOOST_CHECK_EQUAL(rc.has_error(), false);

  control.set_periodic_update_check_interval(std::chrono::seconds{1});
  control.set_update_available_callback([&]() -> boost::asio::awaitable<unfold::UpdateResponse> {
    spdlog::info("Update available");
    io_context.stop();
    co_return unfold::UpdateResponse::Later;
  });

  control.set_periodic_update_check_enabled(true);

  io_context.wait();
  server.stop();
}

BOOST_AUTO_TEST_SUITE_END()
