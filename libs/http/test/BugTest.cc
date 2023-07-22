#include <string>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/url/url.hpp>
#include <boost/url/url_view.hpp>

class Foo
{
public:
  boost::asio::awaitable<void> bar();

private:
  boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12_client};
  std::shared_ptr<boost::beast::ssl_stream<boost::beast::tcp_stream>> stream;
};

boost::asio::awaitable<void>
Foo::bar()
{
  auto executor = co_await boost::asio::this_coro::executor;
  stream = std::make_shared<boost::beast::ssl_stream<boost::beast::tcp_stream>>(executor, ctx);
}

int
main(int argc, char **argv)
{
  Foo foo;

  boost::asio::io_context ioc;
  boost::asio::co_spawn(
    ioc,
    [&]() -> boost::asio::awaitable<void> { co_await foo.bar(); },
    boost::asio::detached);
  ioc.run();
  ioc.restart();
}
