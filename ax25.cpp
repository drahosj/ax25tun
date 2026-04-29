#include "ax25.h"

#include <format>
Expected<std::array<char, 7>> AX25Address::pack(void) const {
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

AX25Address::AX25Address(std::string c, int s) : _call{c}, _ssid(s) {}

AX25Address::AX25Address(std::span<char, 7> packed) {
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

std::string AX25Address::call() const { return _call; }
int AX25Address::ssid() const { return _ssid; }
std::string AX25Address::str() const {return std::format("{}-{}", _call, _ssid);}

Expected<AX25Address> unpack_ax25addr(std::span<char> packed)
{
  if (packed.size() != 7) {
    return Unexpected{
      std::format("Tried to unpack address size {}", packed.size())};
  }

  return AX25Address{std::span<char, 7>{packed.begin(), packed.end()}};
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
