#include <iostream>
#include <vector>
#include <expected>
#include <string>
#include <format>
#include <cerrno>
#include <cstring>
#include <array>
#include <span>
#include <unordered_map>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "endian.h"

static int conn;

template <class T>
using Expected = std::expected<T, std::string>;
using Unexpected = std::unexpected<std::string>;

class AX25Address {
  private:
    std::string _call;
    int _ssid;

  public:
    Expected<std::array<char, 7>> pack(void) const {
      if (_call.size() > 6) {
        return Unexpected{"Callsign too long"};
      }
      if (_ssid < 0 || _ssid > 15) {
        return Unexpected{"SSID out of range"};
      }
      std::array<char, 7> packed;
      packed.fill(0x40);
      for (int i = 0; i < _call.size(); i++) {
        packed[i] = _call[i] << 1;
      }
      packed[6] = 0x60 | (_ssid << 1);

      return packed;
    }

    AX25Address() = default;
    AX25Address(std::string c, int s) : _call{c}, _ssid(s) {}

    std::string call() const { return _call; }
    int ssid() const { return _ssid; }
};

void hexdump(std::span<char> s)
{
  for(auto c : s) {
    std::cout << std::format("{:02x} ", c);
  }
  std::cout << std::endl;
}

static std::unordered_map<uint32_t, AX25Address> ipv4_arp_table;

std::vector<char> kiss_frame(std::span<char> data)
{
  std::vector<char> out;
  out.reserve(data.size() + 2);
  out.push_back(0xc0);
  out.push_back(0x00);
  for(auto c : data) {
    if (c == (char) 0xc0) {
      out.push_back(0xdb);
      out.push_back(0xdc);
    } else if (c == (char) 0xdb) {
      out.push_back(0xdb);
      out.push_back(0xdd);
    } else {
      out.push_back(c);
    }
  }
  out.push_back(0xc0);
  return out;
}

Expected<std::vector<char>> ax25_frame(
    const AX25Address dst, const AX25Address src,
    int control, int proto, std::span<char> data)
{
  std::vector<char> out;
  out.reserve(data.size() + 16);
  auto _d = dst.pack();
  if (!_d) {
    return Unexpected{_d.error()};
  }
  auto _s = src.pack();
  if (!_s) {
    return Unexpected{_s.error()};
  }
  auto d = _d.value();
  auto s = _s.value();
  s[6] |= 0x01;
  out.insert(out.end(), d.begin(), d.end());
  out.insert(out.end(), s.begin(), s.end());
  out.push_back(control & 0xff);
  out.push_back(proto & 0xff);
  out.insert(out.end(), data.begin(), data.end());

  return out;
}

std::string errno_msg(const std::string & msg = "")
{
  if (!msg.empty()) {
    return std::format("{}: {}", msg, std::strerror(errno));
  } else {
    return std::strerror(errno);
  }
}

std::string inet_ntop(const in_addr addr)
{
    std::array<char, 16> buf;
    if (inet_ntop(AF_INET, &addr, buf.data(), buf.size()) == nullptr) {
      throw "INET_NTOP unexpectedly failed";
    }
    return std::string{buf.data()};
}

std::string inet_ntop(uint32_t addr)
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

void print_ipv4_arp_table()
{
  std::cout << "ARP Table:\n";
  for (auto i : ipv4_arp_table) {
    auto s = inet_ntop(i.first);
    std::cout << std::format(
        "\t{} -> {}-{}\n", 
        s, i.second.call(), i.second.ssid());
  }
}

Expected<void> arp_add_ipv4(const std::string ip, 
    const AX25Address ax25)
{
  auto ina = inet_pton(ip);
  if (!ina) {
    return Unexpected{ina.error()};
  }

  if (ax25.ssid() < 0 || ax25.ssid() > 15) {
    return Unexpected{std::format("SSID out of range ({})", ax25.ssid())};
  }

  ipv4_arp_table[ina.value().s_addr] = ax25;

  return Expected<void>{};
}


Expected<int> tun_alloc(const std::string_view dev)
{
  ifreq ifr{};
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    return Unexpected{errno_msg("open(/dev/net/tun)")};
  }

  ifr.ifr_flags = IFF_TUN;
  if (!dev.empty()) {
    auto s = dev.substr(0, IFNAMSIZ-1);
    std::memcpy(&ifr.ifr_name, s.data(), s.size());
  }

  if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
    close(fd);
    return Unexpected{errno_msg("ioctl(TUNSETIFF)")};
  }

  return fd;
}

struct PacketInfo {
  uint16_t flags;
  uint16_t proto;
};

struct IPv4Header {
  uint32_t v_ihl_tos_length;
  uint32_t id_offset;
  uint32_t ttl_proto_checksum;
  uint32_t srcaddr;
  uint32_t dstaddr;

  void fix_endianness() {
    BE(v_ihl_tos_length);
    BE(id_offset);
    BE(ttl_proto_checksum);
  }
};

Expected<void> handle_ipv4_packet(std::span<char> &packet)
{
  if (packet.size() < sizeof(IPv4Header)) {
    return Unexpected{"packet to small to contain ipv4 header"};
  }

  IPv4Header hdr;
  memcpy(&hdr, packet.data(), sizeof(hdr));

  std::cout << std::format("\t\tsrc: {}\n\t\tdst: {}\n",
      inet_ntop(hdr.srcaddr), inet_ntop(hdr.dstaddr));

  std::cout << std::format("\t\tproto: {}\n", 
      (hdr.ttl_proto_checksum >> 8) & 0xff);

  if (ipv4_arp_table.contains(hdr.dstaddr)) {
    auto dst = ipv4_arp_table[hdr.dstaddr];
    std::cout << std::format("\t\tDst found in arp table: {}-{}\n",
      dst.call(), dst.ssid()) << std::endl;

    AX25Address src{"WN0NW", 1};
    auto ax25 = ax25_frame(dst, src, 0x03, 0xcc, packet);
    if (!ax25) {
      return Unexpected{ax25.error()};
    }
    auto kiss = kiss_frame(ax25.value());

    std::cout << "\t\tSending to KISS TNC:" << std::endl;
    std::cout << std::format("\t\t\tKISS frame length: {}\n",
        kiss.size());
    hexdump(kiss);
    auto res = send(conn, kiss.data(), kiss.size(), 0);
    std::cout << "\t\t\tsend() returned " << res << std::endl;
  }

  return Expected<void>{};
}

Expected<void> parse_packet(const std::span<char> &data)
{
  PacketInfo pi;
  if (data.size() < sizeof(pi)) {
    return Unexpected{"data too small for pi"};
  }
  std::memcpy(&pi, data.data(), sizeof(pi));
  pi.proto = be(pi.proto);
  std::span<char> packet{data.begin() + 4, data.end()};
  std::cout << std::format("Packet info:\n\tFlags: {:#x}\n\tProto: {:#x}\n",
      pi.flags, pi.proto);
  std::cout << std::format("\tSize: {}\n", packet.size());

  if (pi.flags & 0x0001) {
    return Unexpected{"Fragmeted TUN frame!"};
  }


  if (pi.proto == 0x800) {
    return handle_ipv4_packet(packet);
  } else {
    return Unexpected{"Unsupported protocol (only ivp4 supported for now)"};
  }


  return Expected<void>{};
}

int main()
{
  auto res = tun_alloc("ax25tun0");
  if (!res) {
    std::cout << "Error: " << res.error() << std::endl;
    return -1;
  }

  int fd = res.value();

  std::cout << "Tun opened." << std::endl;

  arp_add_ipv4("10.1.0.2", AX25Address{"WN0NW", 2});
  arp_add_ipv4("10.1.0.3", AX25Address{"WN0NW", 3});
  arp_add_ipv4("10.1.0.4", AX25Address{"KE0CDT", 1});

  print_ipv4_arp_table();

  conn = socket(AF_INET, SOCK_STREAM, 0);
  if (conn < 1) {
    std::cout << "Error: " << errno_msg("socket()") << std::endl;
    return -1;
  }

  sockaddr_in sin{};
  sin.sin_family = AF_INET;
  sin.sin_port = be((uint16_t) 8001);
  sin.sin_addr = inet_pton("127.0.0.1").value();

  if (connect(conn, (sockaddr *) &sin, sizeof(sin)) < 0) {
    std::cout << "Error: " << errno_msg("connect()") << std::endl;
    return -1;
  }
  std::cout << "Connected to Direwolf KISS" << std::endl;
  std::cout << "KISS FD: " << conn << std::endl;


  std::cout << "Entering read loop." << std::endl;
  for(;;) {
    std::array<char, 1500> buf;
    auto len = read(fd, buf.data(), buf.size());
    std::cout << "read() returned " << len << std::endl;
    if (len < 0) {
      std::cout << "Error: " << errno_msg("read()") << std::endl;
      break;
    }
    std::span<char> data{buf.begin(), (long unsigned int) len};
    auto res = parse_packet(data);
    if (!res) {
      std::cout << "Packet error: " << res.error() << std::endl;
    }
  }
}
