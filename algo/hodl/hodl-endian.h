#ifndef HODL_BYTESWAP_H
#define HODL_BYTESWAP_H 1

#define __bswap_constant_16(x) \
     ((unsigned short int) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))

static __inline unsigned short int
__bswap_16 (unsigned short int __bsx)
{
  return __bswap_constant_16 (__bsx);
}

// LE
#  define htobe16(x) __bswap_16 (x)
#  define htole16(x) (x)
#  define be16toh(x) __bswap_16 (x)
#  define le16toh(x) (x)

// BE
//#  define htole16(x) __bswap_16 (x)
//#  define htobe16(x) (x)
//#  define le16toh(x) __bswap_16 (x)
//#  define be16toh(x) (x)

#define __bswap_constant_32(x) \
     ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |		      \
      (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))

static __inline unsigned int
__bswap_32 (unsigned int __bsx)
{
  return __builtin_bswap32 (__bsx);
}

// LE	  
#  define htobe32(x) __bswap_32 (x)
#  define htole32(x) (x)
#  define be32toh(x) __bswap_32 (x)
#  define le32toh(x) (x)

// BE
//#  define htole32(x) __bswap_32 (x)
//#  define htobe32(x) (x)
//#  define le32toh(x) __bswap_32 (x)
//#  define be32toh(x) (x)

# define __bswap_constant_64(x) \
     ((((x) & 0xff00000000000000ull) >> 56)				      \
      | (((x) & 0x00ff000000000000ull) >> 40)				      \
      | (((x) & 0x0000ff0000000000ull) >> 24)				      \
      | (((x) & 0x000000ff00000000ull) >> 8)				      \
      | (((x) & 0x00000000ff000000ull) << 8)				      \
      | (((x) & 0x0000000000ff0000ull) << 24)				      \
      | (((x) & 0x000000000000ff00ull) << 40)				      \
      | (((x) & 0x00000000000000ffull) << 56))

static __inline uint64_t
__bswap_64 (uint64_t __bsx)
{
  return __bswap_constant_64 (__bsx);
}

// LE
#  define htobe64(x) __bswap_64 (x)
#  define htole64(x) (x)
#  define be64toh(x) __bswap_64 (x)
#  define le64toh(x) (x)

// BE
//#  define htole64(x) __bswap_64 (x)
//#  define htobe64(x) (x)
//#  define le64toh(x) __bswap_64 (x)
//#  define be64toh(x) (x)

#endif