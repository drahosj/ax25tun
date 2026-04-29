#ifndef _arp_h
#define _arp_h

#include <vector>
#include <unordered_map>
#include <string>
#include <optional>

#include <netinet/in.h>

#include "util.h"
#include "ax25.h"

enum class AddressType {
    IPV4,
    IPv6
};


struct IpAddress {
    AddressType type;
    union {
        in_addr inet;
        in6_addr inet6;
    };
    IpAddress() = default;
};

struct ArpTableEntry {
   //int _empty; 
};

class Arp {
private:
//    std::unordered_map<IpAddress, ArpTableEntry> _arp_table;
};

Expected<std::vector<char>> make_arp4_packet(int opcode,
    const AX25Address src_ax25, const AX25Address dst_ax25,
    std::uint32_t srcaddr, std::uint32_t dstaddr);

void print_ipv4_arp_table();
Expected<void> arp_add_ipv4(const std::string ip, 
    const AX25Address ax25);
bool is_our_ipv4(uint32_t ipv4, const std::string &ifname);

extern std::unordered_map<std::uint32_t, AX25Address> ipv4_arp_table;

Expected<void> handle_arp4_packet(std::span<char> arp, 
    const std::string & ifname, const AX25Address & myaddr);

#endif
