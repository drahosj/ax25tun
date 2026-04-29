#include "arp.h"
#include "util.h"

#include <format>
#include <iostream>
#include <cstring>

#include <ifaddrs.h>

std::unordered_map<std::uint32_t, AX25Address> ipv4_arp_table{};

Expected<std::vector<char>> make_arp4_packet(int opcode,
    const AX25Address src_ax25, const AX25Address dst_ax25,
    std::uint32_t srcaddr, std::uint32_t dstaddr)
{
  /* AX.25/IPv4 ARP header */
  std::array<char, 6> hdr = {0x00, 0x03, 0x00, (char) 0xcc, 0x07, 0x04};
  std::vector<char> out;
  out.reserve(32);
  out.insert(out.end(), hdr.begin(), hdr.end());
  out.push_back((char) ((opcode >> 8) & 0xff));
  out.push_back((char) (opcode & 0xff));

  auto sender = src_ax25.pack();
  if (!sender) {
    return Unexpected{sender.error()};
  }
  out.insert(out.end(), sender.value().begin(), sender.value().end());

  std::array<char, 4> buf;
  std::memcpy(buf.data(), &srcaddr, buf.size());
  out.insert(out.end(), buf.begin(), buf.end());
  auto target = dst_ax25.pack();
  if (!sender) {
    return Unexpected{target.error()};
  }
  out.insert(out.end(), target.value().begin(), target.value().end());
  std::memcpy(buf.data(), &dstaddr, buf.size());
  out.insert(out.end(), buf.begin(), buf.end());

  return out;
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


bool is_our_ipv4(uint32_t ipv4, const std::string &ifname)
{
  ifaddrs *ifaddr;

  if (getifaddrs(&ifaddr) == -1) {
    std::cout << errno_msg("getifaddrs") << std::endl;
    return false;
  }

  bool found = false;
  for (ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == nullptr) {
      continue;
    }

    int family = ifa->ifa_addr->sa_family;
    if (family != AF_INET) {
      continue;
    }

    if (((sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr == ipv4) {
      std::cout << "\t\t\tMatched IP address\n";
      std::cout << "\t\t\tMatched IF: " << ifa->ifa_name << std::endl;
      if (!std::strcmp(ifname.c_str(), ifa->ifa_name)) {
        found = true;
        std::cout << "\t\t\t\ton correct interface.\n";
        break;
      } else {
        std::cout << "\t\t\t\tIP belongs to a different interface. Weird!\n";
      }
    }
  }

  freeifaddrs(ifaddr);
  return found;
}

Expected<void> send_packet(AX25Address dst, int proto, std::span<char> packet);
Expected<void> handle_arp4_packet(std::span<char> arp, const std::string & ifname, const AX25Address & myaddr)
{
  if (arp.size() < 30) {
    return Unexpected{std::format("ARP packet too small: {}", arp.size())};
  }

  int hwtype = ((arp[0] & 0xff) << 8) | (arp[1] & 0xff) ;
  int prototype = ((arp[2] & 0xff) << 8) | (arp[3] & 0xff) ;
  int hwsize = arp[4] & 0xff;
  int protosize = arp[5] & 0xff;
  int opcode = ((arp[6] & 0xff) << 8) | (arp[7] & 0xff) ;

  if (hwsize != 7) {
    return Unexpected{std::format("\t\tIncorrect hwsize {}\n", hwsize)};
  }

  if (protosize != 4) {
    return Unexpected{std::format("\t\tIncorrect protosize {}\n", protosize)};
  }

  if (prototype != 0x00cc) {
    std::cout << std::format("\t\tWeird protocol type {}\n", prototype);
  }

  AX25Address sender_ax25{std::span<char, 7>{&arp[8], &arp[15]}};
  uint32_t sender_ip;
  memcpy(&sender_ip, &arp[15], 4);

  AX25Address target_ax25{std::span<char, 7>{&arp[19], &arp[26]}};
  uint32_t target_ip;
  memcpy(&target_ip, &arp[26], 4);

  if (sender_ip != 0 && !sender_ax25.call().empty()) {
    std::cout << "\t\tPopulating ARP table with sender information\n";
    ipv4_arp_table[sender_ip] = sender_ax25;
    print_ipv4_arp_table;
  }
  
  std::optional<std::vector<char>> out{};

  if (opcode == 1) {
    std::cout << "\t\tHandling ARP request\n";
    std::cout << "\t\t\tTarget IP: " << inet_ntop(target_ip) << std::endl;
    if (is_our_ipv4(target_ip, ifname)) {
      std::cout << "\t\t\tARP request for us!\n";
      auto arp = make_arp4_packet(0x02, 
          myaddr, sender_ax25, target_ip, sender_ip);
      if (!arp) {
        return Unexpected{arp.error()};
      }
      return send_packet(sender_ax25, 0xcd, arp.value());
    }
  }

  return Expected<void>{};
}
