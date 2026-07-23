//** Introduction
// This file contains utility functions to help using the external Math library
#include "Tpm.h"
#include "TpmMath_Util_fp.h"

//*** TpmMath_IntFrom2B()
// Convert an TPM2B to a Crypt_Int.
// If the input value does not exist, or the output does not exist, or the input
// will not fit into the output the function returns NULL
LIB_EXPORT Crypt_Int* TpmMath_IntFrom2B(Crypt_Int*   value,  // OUT:
                                        const TPM2B* a2B     // IN: number to convert
)
{
    if(value != NULL && a2B != NULL)
        return ExtMath_IntFromBytes(value, a2B->buffer, a2B->size);
    return NULL;
}

//*** TpmMath_IntTo2B()
//
// Function to convert a Crypt_Int to TPM2B. The TPM2B bytes are
// always in big-endian ordering (most significant byte first). If 'size' is
// non-zero and less than required by `value` then an error is returned. If
// `size` is non-zero and larger than `value`, the result buffer is padded
// with zeros. If `size` is zero, then the TPM2B is assumed to be large enough
// for the data and a2b->size will be adjusted accordingly.
LIB_EXPORT BOOL TpmMath_IntTo2B(
    const Crypt_Int* value,  // IN: value to convert
    TPM2B*           a2B,    // OUT: buffer for output
    NUMBYTES         size    // IN: Size of output buffer - see comments.
)
{
    // Set the output size
    if(value && a2B)
    {
        a2B->size = size;
        return ExtMath_IntToBytes(value, a2B->buffer, &a2B->size);
    }
    return FALSE;
}

//*** TpmMath_GetRandomBits()
// This function gets random bits for use in various places.
//
// One consequence of the generation scheme is that, if the number of bits requested
// is not a multiple of 8, then the high-order bits are set to zero. This would come
// into play when generating a 521-bit ECC key. A 66-byte (528-bit) value is
// generated and the high order 7 bits are masked off (CLEAR).
// In this situation, the highest order byte is the first byte (big-endian/TPM2B format)
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure
LIB_EXPORT BOOL TpmMath_GetRandomBits(BYTE* pBuffer, size_t bits, RAND_STATE* rand)
{
    // buffer is assumed to be large enough for the number of bits rounded up to
    // bytes.
    NUMBYTES byteCount = (NUMBYTES)BITS_TO_BYTES(bits);
    if(DRBG_Generate(rand, pBuffer, byteCount) == byteCount)
    {
        // now flip the buffer order - this exists only to maintain
        // compatibility with existing Known-value tests that expect the
        // GetRandomInteger behavior of generating the value in little-endian
        // order.
        BYTE* pFrom = pBuffer + byteCount - 1;
        BYTE* pTo   = pBuffer;
        while(pTo < pFrom)
        {
            BYTE t = *pTo;
            *pTo   = *pFrom;
            *pFrom = t;
            pTo++;
            pFrom--;
        }
        // For a little-endian machine, the conversion is a straight byte
        // reversal, done above. For a big-endian machine, we have to put the
        // words in big-endian byte order.  COMPATIBILITY NOTE: This code does
        // not exactly reproduce the original code, because the original big-num
        // code always generated data in units of crypt_word_t sizes.  I.e. you
        // couldn't generate just 9 bits for example.  This revised version of
        // the function could; and would generate 2 bytes with the first byte
        // masked to 1 bit.  In order to avoid running over the buffer when
        // swapping crypt_uword_t blocks, this loop intentionally doesn't swap
        // the last word if it is smaller than crypt_word_t size (which is the
        // same as saying the buffer isn't an integral number of crypt_word_t
        // units.) This is okay in this particular case _because_ this whole
        // block of swapping code is to maintain compatibilty with existing
        // KNOWN ANSWER TESTS, and said existing tests use sizes that this
        // assumption is true for.  Any new code with a different size where
        // this last partial value isn't swapped will be creating a new KAT, and
        // thus any (cryptographically valid) value is still random; swapping
        // doesn't make a cryptographic random buffer more or less random, so
        // the failure to swap is fine.
#if BIG_ENDIAN_TPM
        crypt_uword_t* pTemp = (crypt_uword_t*)pBuffer;
        for(size_t t = 0; t < (byteCount / sizeof(crypt_uword_t)); t++)
            *pTemp = SWAP_CRYPT_WORD(*pTemp);
#endif
        // if the number of bits % 8 != 0, mask the high order (first) byte to the relevant number of bits
        // bits % 8     desired mask   right-shift of 0xFF
        //     0           0xFF             0 = (8 - 0) % 8
        //     1           0x01             7 = (8 - 1) % 8
        //     2           0x03             6 = (8 - 2) % 8
        //     ... etc ...
        //     7           0x7F             1 = (8 - 7) % 8
        static const BYTE mask[8] = {0xff, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f};
        int excessBits            = bits % 8;
        pBuffer[0]                = pBuffer[0] & mask[excessBits];
        return TRUE;
    }
    return FALSE;
}

//*** TpmMath_GetRandomInteger()
// This function gets random bits for use in various places. To make sure that the
// number is generated in a portable format, it is created as a TPM2B and then
// converted to the internal format.
//
// One consequence of the generation scheme is that, if the number of bits requested
// is not a multiple of 8, then the high-order bits are set to zero. This would come
// into play when generating a 521-bit ECC key. A 66-byte (528-bit) value is
// generated an the high order 7 bits are masked off (CLEAR).
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure
LIB_EXPORT BOOL TpmMath_GetRandomInteger(Crypt_Int* n, size_t bits, RAND_STATE* rand)
{
    // Since this could be used for ECC key generation using the extra bits method,
    // make sure that the value is large enough
    TPM2B_TYPE(LARGEST, LARGEST_NUMBER + 8);
    TPM2B_LARGEST large;
    //
    large.b.size = (UINT16)BITS_TO_BYTES(bits);
    if(DRBG_Generate(rand, large.t.buffer, large.t.size) == large.t.size)
    {
        if(TpmMath_IntFrom2B(n, &large.b) != NULL)
        {
            if(ExtMath_MaskBits(n, (crypt_uword_t)bits))
                return TRUE;
        }
    }
    return FALSE;
}

//*** BnGenerateRandomInRange()
// This function is used to generate a random number r in the range 1 <= r < limit.
// The function gets a random number of bits that is the size of limit. There is some
// some probability that the returned number is going to be greater than or equal
// to the limit. If it is, try again. There is no more than 50% chance that the
// next number is also greater, so try again. We keep trying until we get a
// value that meets the criteria. Since limit is very often a number with a LOT of
// high order ones, this rarely would need a second try.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure ('limit' is too small)
LIB_EXPORT BOOL TpmMath_GetRandomInRange(
    Crypt_Int* dest, const Crypt_Int* limit, RAND_STATE* rand)
{
    size_t bits = ExtMath_SizeInBits(limit);
    //
    if(bits < 2)
    {
        ExtMath_SetWord(dest, 0);
        return FALSE;
    }
    else
    {
        while(TpmMath_GetRandomInteger(dest, bits, rand)
              && (ExtMath_IsZero(dest) || (ExtMath_UnsignedCmp(dest, limit) >= 0)))
            ;
    }
    return !_plat__InFailureMode();
}
