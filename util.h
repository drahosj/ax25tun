#ifndef _util_h
#define _util_h

#include <cstdint>
#include <expected>
#include <string>
#include <span>

#include <arpa/inet.h>

template <class T>
using Expected = std::expected<T, std::string>;
using Unexpected = std::unexpected<std::string>;

std::string errno_msg(const std::string & msg = "");
void hexdump(std::span<char> s);

std::string inet_ntop(const in_addr addr);
std::string inet_ntop(std::uint32_t addr);
Expected<in_addr> inet_pton(const std::string addr);

#endif
