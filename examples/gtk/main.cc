
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

#ifdef WIN32
#  include <windows.h>
#endif

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>

#include <gtkmm.h>

#include "UpdateDialog.hh"

#include "http/HttpServer.hh"
#include "unfold/Unfold.hh"
#include "unfold/coro/gtask.hh"
#include "unfold/coro/IOContext.hh"

#if defined(WIN32)
int APIENTRY
wWinMain(HINSTANCE, HINSTANCE, wchar_t *, int)
{
  return 1;
}
#endif

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

unfold::coro::gtask<void>
coro_check(Glib::RefPtr<Gtk::Application> app, std::shared_ptr<unfold::Unfold> updater)
{
  auto update_available = co_await updater->check_for_update();
  if (!update_available)
    {
      co_return;
    }

  if (update_available.value())
    {
      auto update_info = updater->get_update_info();
      auto *dlg = new UpdateDialog(update_info);
      dlg->show();
      dlg->signal_response().connect([app](int response) {
        spdlog::info("User response: {} ", response);
        app->quit();
      });

      // TODO: leak
    }
}

int
main(int argc, char *argv[])
{
#if defined(WIN32)
  SetEnvironmentVariableA("GTK_DEBUG", nullptr);
  SetEnvironmentVariableA("G_MESSAGES_DEBUG", nullptr);
  // No auto hide scrollbars
  SetEnvironmentVariableA("GTK_OVERLAY_SCROLLING", "0");
  // No Windows-7 style client-side decorations on Windows 10...
  SetEnvironmentVariableA("GTK_CSD", "0");
  SetEnvironmentVariableA("GDK_WIN32_DISABLE_HIDPI", "1");
#endif

  spdlog::set_level(spdlog::level::debug);

  unfold::http::HttpServer server;
  server.add_file("/appcast.xml", "../../test/appcast.xml");
  server.add_file("/workrave-1.11.0-alpha.1.exe", "../../test/junk");
  server.add_file("/installer.sh", "../../test/installer.sh");
  server.run();

  unfold::coro::IOContext io_context;
  auto updater = unfold::Unfold::create(io_context);

  auto rc = updater->set_appcast("https://127.0.0.1:1337/appcast.xml");
  if (!rc)
    {
      spdlog::info("Invalid appcast URL");
      return 1;
    }

  updater->set_certificate(cert);
  // TODO: fix
  // if (!rc)
  //   {
  //     spdlog::info("Invalid certificate");
  //     return 1;
  //   }

  rc = updater->set_signature_verification_key("MCowBQYDK2VwAyEA0vkFT/GcU/NEM9xoDqhiYK3/EaTXVAI95MOt+SnjCpM=");
  if (!rc)
    {
      spdlog::info("Invalid signature key");
      return 1;
    }

  rc = updater->set_current_version("1.10.43");
  if (!rc)
    {
      spdlog::info("Invalid version");
      return 1;
    }

  spdlog::info("Creating app");
  auto app = Gtk::Application::create();
  app->register_application();
  app->hold();

  unfold::coro::glib::scheduler scheduler(g_main_context_default(), io_context.get_io_context());

  Glib::signal_timeout().connect([]() { return 1; }, 500);

  Glib::signal_timeout().connect(
    [updater, &app, &scheduler]() {
      spdlog::info("check");

      unfold::coro::gtask<void> task = coro_check(app, updater);
      scheduler.spawn(std::move(task));
      return 0;
    },
    2000);
  Glib::RefPtr<Glib::MainContext> context = Glib::MainContext::get_default();

  app->run();

  // spdlog::info("Creating update dialog.");
  // spdlog::info("Showing update dialog.");
  // app->hold();
  // dlg->show();
  // spdlog::info("Running main loop.");
  // dlg->hide();
  // spdlog::info("complete:");

  server.stop();

  return 0;
}
