#include "kiss.h"

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
