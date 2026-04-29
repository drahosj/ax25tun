#include "util.h"

#include <format>
#include <iostream>

#include <cstring>
#include <cerrno>

std::string errno_msg(const std::string & msg)
{
  if (!msg.empty()) {
    return std::format("{}: {}", msg, std::strerror(errno));
  } else {
    return std::strerror(errno);
  }
}

void hexdump(std::span<char> s)
{
  for(auto c : s) {
    std::cout << std::format("{:02x} ", c);
  }
  std::cout << std::endl;
}


std::string inet_ntop(const in_addr addr)
{
  std::array<char, 16> buf;
  if (inet_ntop(AF_INET, &addr, buf.data(), buf.size()) == nullptr) {
    throw "INET_NTOP unexpectedly failed";
  }
  return std::string{buf.data()};
}

std::string inet_ntop(std::uint32_t addr)
{
  return inet_ntop(in_addr{addr});
}

Expected<in_addr> inet_pton(const std::string addr)
{
  in_addr ina;
  if (!inet_pton(AF_INET, addr.c_str(), &ina)) {
    return Unexpected{errno_msg(std::format("inet_pton({})", addr))};
  }

  return ina;
}
