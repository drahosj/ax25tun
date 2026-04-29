#ifndef _ax25_h
#define _ax25_h

#include "util.h"

#include <array>
#include <string>
#include <span>
#include <vector>

class AX25Address {
  private:
    std::string _call;
    int _ssid;

  public:
    Expected<std::array<char, 7>> pack(void) const;

    AX25Address() = default;
    AX25Address(std::string c, int s);
    AX25Address(std::span<char, 7> packed);

    std::string call() const;
    int ssid() const;

    std::string str() const;
};

Expected<AX25Address> unpack_ax25addr(std::span<char> packed);

Expected<std::vector<char>> ax25_frame(
    const AX25Address dst, const AX25Address src,
    int control, int proto, std::span<char> data);

#endif
