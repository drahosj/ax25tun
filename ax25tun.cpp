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
#include <ifaddrs.h>
#include <sys/epoll.h>

#include "endian.h"

static int conn;
static int tunfd;

template <class T>
using Expected = std::expected<T, std::string>;
using Unexpected = std::unexpected<std::string>;

class AX25Address {
  private:
    std::string _call;
    int _ssid;

  public:
    Expected<std::array<char, 7>> pack(void) const {
      if (_call.empty()) {
        std::array<char, 7> out{};
        out.fill(0);
        return out;
      }
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
    AX25Address(std::span<char, 7> packed) {
      for (int i = 0; i < 6; i++) {
        char c = packed[i];
        if (c == (char) 0x00) {
          _call = "";
          break;
        } else if (c != (char) 0x40) {
          _call.push_back((c >> 1) & 0x7f);
        }
        _ssid = (packed[6] >> 1) & 0x0f;
      }
    }

    std::string call() const { return _call; }
    int ssid() const { return _ssid; }

    std::string str() const {return std::format("{}-{}", _call, _ssid);}
};

Expected<AX25Address> unpack_ax25addr(std::span<char> packed)
{
  if (packed.size() != 7) {
    return Unexpected{
      std::format("Tried to unpack address size {}", packed.size())};
  }

  return AX25Address{std::span<char, 7>{packed.begin(), packed.end()}};
}

void hexdump(std::span<char> s)
{
  for(auto c : s) {
    std::cout << std::format("{:02x} ", c);
  }
  std::cout << std::endl;
}

static std::unordered_map<std::uint32_t, AX25Address> ipv4_arp_table{};
static std::vector<std::vector<char>> queued_packets{};

static AX25Address myaddr{"WN0NW", 1};

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

#ifdef USE_PI
  ifr.ifr_flags = IFF_TUN;
#else
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
#endif
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
  std::uint16_t flags;
  std::uint16_t proto;
};

struct IPv4Header {
  std::uint32_t v_ihl_tos_length;
  std::uint32_t id_offset;
  std::uint32_t ttl_proto_checksum;
  std::uint32_t srcaddr;
  std::uint32_t dstaddr;

  void fix_endianness() {
    BE(v_ihl_tos_length);
    BE(id_offset);
    BE(ttl_proto_checksum);
  }
};

Expected<void> send_packet(AX25Address dst, int proto, std::span<char> packet)
{
  auto ax25 = ax25_frame(dst, myaddr, 0x03, proto, packet);
  if (!ax25) {
    return Unexpected{ax25.error()};
  }
  auto kiss = kiss_frame(ax25.value());

  std::cout << "\t\tSending to KISS TNC:" << std::endl;
  std::cout << std::format("\t\t\tKISS frame length: {}\n",
      kiss.size());
  //hexdump(kiss);
  auto res = send(conn, kiss.data(), kiss.size(), 0);
  std::cout << "\t\t\tsend() returned " << res << std::endl;

  return Expected<void>{};
}

Expected<void> handle_ipv4_packet(std::span<char> packet)
{
  if (packet.size() < sizeof(IPv4Header)) {
    return Unexpected{"packet to small to contain ipv4 header"};
  }

  if (packet[3] & 0x0f != 4) {
    return Unexpected{"IP version not 4"};
  }


  IPv4Header hdr;
  std::memcpy(&hdr, packet.data(), sizeof(hdr));

  std::cout << std::format("\t\tsrc: {}\n\t\tdst: {}\n",
      inet_ntop(hdr.srcaddr), inet_ntop(hdr.dstaddr));

  std::cout << std::format("\t\tproto: {}\n", 
      (hdr.ttl_proto_checksum >> 8) & 0xff);

  if (ipv4_arp_table.contains(hdr.dstaddr)) {
    auto dst = ipv4_arp_table[hdr.dstaddr];
    std::cout << std::format("\t\tDst found in arp table: {}-{}\n",
        dst.call(), dst.ssid()) << std::endl;

    send_packet(dst, 0xcc, packet);
  } else {
    std::cout << "\t\t\tNo cached ARP entry for dst!" << std::endl;
    auto arp_req = make_arp4_packet(0x01, 
        myaddr, AX25Address{}, hdr.srcaddr, hdr.dstaddr);
    if (!arp_req) {
      return Unexpected{std::string{"make_arp4_request(): "} + arp_req.error()};
    }
    std::cout << "\t\t\tSending ARP req." << std::endl;
    AX25Address qst{"QST", 0};
    send_packet(qst, 0xcd, arp_req.value());
    queued_packets.push_back(std::vector<char>{packet.begin(), packet.end()});
    std::cout << "\t\t\tPacket queued for later transmit" << std::endl;
    std::cout << "\t\t\t\tTotal queued packets: " << queued_packets.size()
      << std::endl;
  }

  return Expected<void>{};
}

Expected<void> parse_packet(const std::span<char> &data)
{
#ifdef USE_PI
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
#else
  handle_ipv4_packet(data);

#endif


  return Expected<void>{};
}

bool is_our_ipv4(uint32_t ipv4)
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
      if (!std::strcmp("ax25tun0", ifa->ifa_name)) {
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

void check_send_queued_packets()
{
  bool again = true;
  while (again) { 
    again = false;
    std::cout << "\tChecking if we can send any queued packets...\n";
    for (auto it = queued_packets.begin(); it < queued_packets.end(); it++) {
      IPv4Header hdr;
      memcpy(&hdr, it->data(), sizeof(hdr));
      if (ipv4_arp_table.contains(hdr.dstaddr)) {
        std::cout << "\t\tIP " << inet_ntop(hdr.dstaddr)
          << "is now in the ARP table! Sending!\n";
        auto dst = ipv4_arp_table[hdr.dstaddr];
        std::cout << std::format("\t\tDst found in arp table: {}-{}\n",
            dst.call(), dst.ssid()) << std::endl;
        send_packet(dst, 0xcc, *it);
        queued_packets.erase(it);
        again = true;
        break;
      }
    }
    std::cout << std::format("\tNow {} queued packets\n", 
        queued_packets.size());
  }
  std::cout << "\tDone checking queue.\n";
}

Expected<void> handle_arp4_packet(std::span<char> arp)
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
    check_send_queued_packets();
  }

  if (opcode == 1) {
    std::cout << "\t\tHandling ARP request\n";
    std::cout << "\t\t\tTarget IP: " << inet_ntop(target_ip) << std::endl;
    if (is_our_ipv4(target_ip)) {
      std::cout << "\t\t\tARP request for us!\n";
      auto arp = make_arp4_packet(0x02, 
          myaddr, sender_ax25, target_ip, sender_ip);
      if (!arp) {
        return Unexpected{arp.error()};
      }
      send_packet(sender_ax25, 0xcd, arp.value());
    }
  }

  return Expected<void>{};
}

Expected<std::vector<char>> unwrap_kiss(std::span<char> kiss)
{
  std::vector<char> kiss_payload{};
  kiss_payload.reserve(kiss.size());
  bool escape_active{false};
  for(char c : kiss) {
    if (escape_active) {
      if (c == 0xdc) {
        kiss_payload.push_back(0xc0);
      } else if (c == 0xdd) {
        kiss_payload.push_back(0xdb);
      } else {
        return Unexpected{std::format("KISS - FESC then {}", c)};
      }
      escape_active = false;
    } else  if (c == 0xdb) {
      escape_active = true;
    } else if (c == 0xc0) {
      return Unexpected{"KISS - FEND in frame???"};
    } else {
      kiss_payload.push_back(c);
    }
  }

  return kiss_payload;
}

Expected<void> handle_kiss_frame(std::span<char> frame)
{
  std::cout << "Handling KISS frame" << std::endl;
  std::cout << "\tLength: " << frame.size() << std::endl;

  if (frame.size() < 17) {
    return Unexpected{std::format("KISS frame only {} bytes", frame.size())};
  }

  if (frame[0] != 0) {
    return Unexpected{std::format("Got unexpected command {}", frame[0])};
  }

  std::span<char> body{frame.begin() + 1, frame.end()};
  auto payload = unwrap_kiss(body);
  if (!payload) {
    return Unexpected{payload.error()};
  }

  auto ax25 = payload.value();
  if (ax25.size() < 16) {
    return Unexpected{std::format("ax25 size only {}", ax25.size())};
  }

  auto _dst = unpack_ax25addr(
      std::span<char>{ax25.begin(), ax25.begin() + 7});
  if (!_dst) {
    return Unexpected{std::format("unpack dst: {}", _dst.error())};
  }
  auto dst = _dst.value();

  auto _src = unpack_ax25addr(
      std::span<char>{ax25.begin() + 7, ax25.begin() + 14});
  if (!_src) {
    return Unexpected{std::format("unpack src: {}", _src.error())};
  }
  auto src = _src.value();

  if (ax25[14] != (0x03)) {
    return Unexpected{std::format("Weird control field {}", ax25[14])};
  }

  int proto = ax25[15] & 0xff;

  std::cout << "\tAX.25 Extracted" << std::endl;
  std::cout << std::format("\t\tdst: {}\n\t\tsrc: {}\n\t\tproto: {:#x}\n",
      dst.str(), src.str(), proto);

  std::span<char> packet{ax25.begin() + 16, ax25.end()};
  std::cout << "\t\tPacket size: " << packet.size() << std::endl;

  if (proto == 0xcc) {
    std::cout << "\t\tIP packet. Writing to tunfd\n";
    std::vector<char> packet_buf{packet.begin(), packet.end()};

#ifdef USE_PI
    PacketInfo pi;
    pi.flags = 0;
    pi.proto = be(0x800);

    std::array<char, 4> pi_buf;
    std::memcpy(pi_buf.data(), &pi, pi_buf.size());

    packet_buf.insert(packet_buf.begin(), pi_buf.begin(), pi_buf.end());
#endif
    std::cout << "\t\t\tpacket_buf size: " << packet_buf.size() << std::endl;
    if (write(tunfd, packet_buf.data(), packet_buf.size()) < 0) {
      return Unexpected{errno_msg("write() packet to tunfd")};
    }
  } else if (proto == 0xcd) {
    std::cout << "\t\tARP packet. Handle internally\n";
    handle_arp4_packet(packet);
  }

  return Expected<void>{};
}

Expected<void> handle_kiss_stream(std::vector<char> &buffer, std::span<char> in)
{
  std::cout << "Handling KISS stream" << std::endl;
  if (buffer.empty()) {
    std::cout << "\tBuffer empty. Scanning for FEND" << std::endl;
    /* If buffer empty, scan for FEND then copy from there to buffer */
    for (auto it = in.begin(); it < in.end(); it++) {
      if (*it == (char) 0xc0) {
        std::cout << "\t\tFEND found\n";
        buffer.insert(buffer.end(), it, in.end());
        break;
      }
    }
  } else {
    std::cout << "\tAppending new data to buffer\n";
    /* Otherwise just append to buffer */
    buffer.insert(buffer.end(), in.begin(), in.end());
  }
  std::cout << "\tScanning buffer. Size: " << buffer.size() << std::endl;
  /* Now scan buffer for frame(s) and handle */
  auto fbegin = buffer.end();
  auto newbegin = buffer.begin();
  for (auto it = buffer.begin(); it < buffer.end(); it++) {
    if (*it == (char) 0xc0) {
      std::cout << "\tFEND encountered\n";
      if (fbegin == buffer.end()) {
        std::cout << "\t\tStart of frame\n";
        fbegin = it;
      } else {
        std::cout << "\tEnd of frame. Handling\n";
        auto res = handle_kiss_frame(std::span<char>{fbegin + 1, it});
        if (!res) {
          std::cout << "KISS frame error: " << res.error() << std::endl;
        }
        fbegin = buffer.end();
        newbegin = it + 1;
      }
    }

    if (newbegin != buffer.begin()) {
      std::cout << "\tResetting buffer\n";
      buffer = std::vector<char>{newbegin, buffer.end()};
    }
  }

  return Expected<void>{};
}

void read_tun()
{
  std::array<char, 1500> buf;
  auto len = read(tunfd, buf.data(), buf.size());
  std::cout << "read() returned " << len << std::endl;
  if (len < 0) {
    std::cout << "Error: " << errno_msg("read()") << std::endl;
    return;
  }
  std::span<char> data{buf.begin(), (long unsigned int) len};
  auto res = parse_packet(data);
  if (!res) {
    std::cout << "Packet error: " << res.error() << std::endl;
  }
}


void read_conn()
{
  std::vector<char> kiss_buffer;
  std::array<char, 1500> buf;
  auto len = read(conn, buf.data(), buf.size());
  std::cout << "read() returned " << len << std::endl;
  if (len < 0) {
    std::cout << "Error: " << errno_msg("read()") << std::endl;
    return;
  }
  std::span<char> data{buf.begin(), (long unsigned int) len};
  auto res = handle_kiss_stream(kiss_buffer, data);
  if (!res) {
    std::cout << "KISS error: " << res.error() << std::endl;
  }
  std::cout << "KISS loop complete. Buffer size: " 
    << kiss_buffer.size()
    << std::endl;
}

int main()
{
  auto res = tun_alloc("ax25tun0");
  if (!res) {
    std::cout << "Error: " << res.error() << std::endl;
    return -1;
  }

  tunfd = res.value();

  std::cout << "Tun opened." << std::endl;

  print_ipv4_arp_table();

  conn = socket(AF_INET, SOCK_STREAM, 0);
  if (conn < 1) {
    std::cout << "Error: " << errno_msg("socket()") << std::endl;
    return -1;
  }

  sockaddr_in sin{};
  sin.sin_family = AF_INET;
  sin.sin_port = be((std::uint16_t) 8001);
  sin.sin_addr = inet_pton("127.0.0.1").value();

  if (connect(conn, (sockaddr *) &sin, sizeof(sin)) < 0) {
    std::cout << "Error: " << errno_msg("connect()") << std::endl;
    return -1;
  }
  std::cout << "Connected to Direwolf KISS" << std::endl;
  std::cout << "KISS FD: " << conn << std::endl;



  int epollfd = epoll_create1(0);
  if (epollfd == -1) {
    std::cout << "Error: " << errno_msg("epoll_create1()") << std::endl;
    return -1;
  }

  struct epoll_event ev;
  ev.events = EPOLLIN;

  ev.data.fd = tunfd;
  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, tunfd, &ev) == -1) {
    std::cout << "Error: " << errno_msg("epoll add tunfd: ") << std::endl;
    return -1;
  }

  ev.data.fd = conn;
  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn, &ev) == -1) {
    std::cout << "Error: " << errno_msg("epoll add conn: ") << std::endl;
    return -1;
  }

  std::cout << "Entering epoll loop." << std::endl;
  for(;;) {
    std::cout << "Waiting\n";

    std::array<epoll_event, 8> events;
    int nfds = epoll_wait(epollfd, events.data(), events.size(), -1);
    if (nfds == -1) {
      std::cout << "Error: " << errno_msg("epoll_wait()") << std::endl;
      return -1;
    }

    for (int i = 0; i < nfds; i++) {
      if (events[i].data.fd == tunfd) {
        std::cout << "\t\ttun event\n";
        read_tun();
      } else if (events[i].data.fd == conn) {
        std::cout << "\t\tconn event\n";
        read_conn();
      } else {
        std::cout << "Weird fd in epoll event!\n";
      }
    }
  }
}


