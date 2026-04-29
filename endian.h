#ifndef _endian_h
#define _endian_h

#include <bit>

template<class T>
constexpr T le(T h)
{
      if constexpr (std::endian::native == std::endian::little)
            return h;
      else if constexpr (std::endian::native == std::endian::big)
            return std::byteswap(h);
}

template<class T>
constexpr T be(T h)
{
      if constexpr (std::endian::native == std::endian::big)
            return h;
      else if constexpr (std::endian::native == std::endian::little)
            return std::byteswap(h);
}

template<class T>
T LE(T &h)
{
  h = le(h);
  return h;
}

template<class T>
T BE(T &h)
{
  h = BE(h);
  return h;
}
#endif
