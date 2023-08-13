#include "windows/WindowsSystemProxy.hh"

#include <string>
#include <iostream>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#if SPDLOG_VERSION >= 10600
#  include <spdlog/pattern_formatter.h>
#endif
#if SPDLOG_VERSION >= 10801
#  include <spdlog/cfg/env.h>
#endif

static void
setup_loggin()
{
  const auto *log_file = "unfold-test.log";

  auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file, false);
  auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

  auto logger{std::make_shared<spdlog::logger>("unfold", std::initializer_list<spdlog::sink_ptr>{file_sink, console_sink})};
  logger->flush_on(spdlog::level::critical);
  spdlog::set_default_logger(logger);

  spdlog::set_level(spdlog::level::debug);
  spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%-5l%$] %v");

#if SPDLOG_VERSION >= 10801
  spdlog::cfg::load_env_levels();
#endif
}

int
main(int argc, char **argv)
{
  setup_loggin();

  WindowsSystemProxy proxy;
  std::optional<std::string> result = proxy.get_system_proxy_for_url_sync("http://www.google.com");
  std::cout << "proxy: " << (result.has_value() ? *result : "x") << std::endl;
  result = proxy.get_system_proxy_for_url_sync("http://www.apple.com");
  std::cout << "proxy: " << (result.has_value() ? *result : "x") << std::endl;
  result = proxy.get_system_proxy_for_url_sync("http://www.microsoft.com");
  std::cout << "proxy: " << (result.has_value() ? *result : "x") << std::endl;
  result = proxy.get_system_proxy_for_url_sync("http://localhost/");
  std::cout << "proxy: " << (result.has_value() ? *result : "x") << std::endl;
  return 0;
}
