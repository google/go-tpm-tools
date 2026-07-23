#ifndef _SWAP_H
#define _SWAP_H

#if LITTLE_ENDIAN_TPM
#  define TO_BIG_ENDIAN_UINT16(i)   REVERSE_ENDIAN_16(i)
#  define FROM_BIG_ENDIAN_UINT16(i) REVERSE_ENDIAN_16(i)
#  define TO_BIG_ENDIAN_UINT32(i)   REVERSE_ENDIAN_32(i)
#  define FROM_BIG_ENDIAN_UINT32(i) REVERSE_ENDIAN_32(i)
#  define TO_BIG_ENDIAN_UINT64(i)   REVERSE_ENDIAN_64(i)
#  define FROM_BIG_ENDIAN_UINT64(i) REVERSE_ENDIAN_64(i)
#else
#  define TO_BIG_ENDIAN_UINT16(i)   (i)
#  define FROM_BIG_ENDIAN_UINT16(i) (i)
#  define TO_BIG_ENDIAN_UINT32(i)   (i)
#  define FROM_BIG_ENDIAN_UINT32(i) (i)
#  define TO_BIG_ENDIAN_UINT64(i)   (i)
#  define FROM_BIG_ENDIAN_UINT64(i) (i)
#endif

#if AUTO_ALIGN == NO

// The aggregation macros for machines that do not allow unaligned access or for
// little-endian machines.

// Aggregate bytes into an UINT

#  define BYTE_ARRAY_TO_UINT8(b)     (uint8_t)((b)[0])
#  define BYTE_ARRAY_TO_UINT16(b)    ByteArrayToUint16((BYTE*)(b))
#  define BYTE_ARRAY_TO_UINT32(b)    ByteArrayToUint32((BYTE*)(b))
#  define BYTE_ARRAY_TO_UINT64(b)    ByteArrayToUint64((BYTE*)(b))
#  define UINT8_TO_BYTE_ARRAY(i, b)  ((b)[0] = (uint8_t)(i))
#  define UINT16_TO_BYTE_ARRAY(i, b) Uint16ToByteArray((i), (BYTE*)(b))
#  define UINT32_TO_BYTE_ARRAY(i, b) Uint32ToByteArray((i), (BYTE*)(b))
#  define UINT64_TO_BYTE_ARRAY(i, b) Uint64ToByteArray((i), (BYTE*)(b))

#else  // AUTO_ALIGN

#  if BIG_ENDIAN_TPM
// the big-endian macros for machines that allow unaligned memory access
// Aggregate a byte array into a UINT
#    define BYTE_ARRAY_TO_UINT8(b)  *((uint8_t*)(b))
#    define BYTE_ARRAY_TO_UINT16(b) *((uint16_t*)(b))
#    define BYTE_ARRAY_TO_UINT32(b) *((uint32_t*)(b))
#    define BYTE_ARRAY_TO_UINT64(b) *((uint64_t*)(b))

// Disaggregate a UINT into a byte array

#    define UINT8_TO_BYTE_ARRAY(i, b) \
        {                             \
            *((uint8_t*)(b)) = (i);   \
        }
#    define UINT16_TO_BYTE_ARRAY(i, b) \
        {                              \
            *((uint16_t*)(b)) = (i);   \
        }
#    define UINT32_TO_BYTE_ARRAY(i, b) \
        {                              \
            *((uint32_t*)(b)) = (i);   \
        }
#    define UINT64_TO_BYTE_ARRAY(i, b) \
        {                              \
            *((uint64_t*)(b)) = (i);   \
        }
#  else
// the little endian macros for machines that allow unaligned memory access
// the big-endian macros for machines that allow unaligned memory access
// Aggregate a byte array into a UINT
#    define BYTE_ARRAY_TO_UINT8(b)  *((uint8_t*)(b))
#    define BYTE_ARRAY_TO_UINT16(b) REVERSE_ENDIAN_16(*((uint16_t*)(b)))
#    define BYTE_ARRAY_TO_UINT32(b) REVERSE_ENDIAN_32(*((uint32_t*)(b)))
#    define BYTE_ARRAY_TO_UINT64(b) REVERSE_ENDIAN_64(*((uint64_t*)(b)))

// Disaggregate a UINT into a byte array

#    define UINT8_TO_BYTE_ARRAY(i, b) \
        {                             \
            *((uint8_t*)(b)) = (i);   \
        }
#    define UINT16_TO_BYTE_ARRAY(i, b)                \
        {                                             \
            *((uint16_t*)(b)) = REVERSE_ENDIAN_16(i); \
        }
#    define UINT32_TO_BYTE_ARRAY(i, b)                \
        {                                             \
            *((uint32_t*)(b)) = REVERSE_ENDIAN_32(i); \
        }
#    define UINT64_TO_BYTE_ARRAY(i, b)                \
        {                                             \
            *((uint64_t*)(b)) = REVERSE_ENDIAN_64(i); \
        }
#  endif  // BIG_ENDIAN_TPM

#endif  // AUTO_ALIGN == NO

#endif  // _SWAP_H
