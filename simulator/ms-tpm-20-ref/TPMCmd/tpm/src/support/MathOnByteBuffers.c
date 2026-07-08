//** Introduction
//
// This file contains implementation of the math functions that are performed
// with canonical integers in byte buffers. The canonical integer is
// big-endian bytes.
//
#include "Tpm.h"
#include "TpmMath_Util_fp.h"

//** Functions

//*** UnsignedCmpB
// This function compare two unsigned values. The values are byte-aligned,
// big-endian numbers (e.g, a hash).
//  Return Type: int
//      1          if (a > b)
//      0          if (a = b)
//      -1         if (a < b)
LIB_EXPORT int UnsignedCompareB(UINT32      aSize,  // IN: size of a
                                const BYTE* a,      // IN: a
                                UINT32      bSize,  // IN: size of b
                                const BYTE* b       // IN: b
)
{
    UINT32 i;
    if(aSize > bSize)
        return 1;
    else if(aSize < bSize)
        return -1;
    else
    {
        for(i = 0; i < aSize; i++)
        {
            if(a[i] != b[i])
                return (a[i] > b[i]) ? 1 : -1;
        }
    }
    // Will return == if sizes are both zero
    return 0;
}

//***SignedCompareB()
// Compare two signed integers:
//  Return Type: int
//      1         if a > b
//      0         if a = b
//      -1        if a < b
int SignedCompareB(const UINT32 aSize,  // IN: size of a
                   const BYTE*  a,      // IN: a buffer
                   const UINT32 bSize,  // IN: size of b
                   const BYTE*  b       // IN: b buffer
)
{
    // are the signs different ?
    if(((a[0] ^ b[0]) & 0x80) > 0)
        // if the signs are different, then a is less than b if a is negative.
        return a[0] & 0x80 ? -1 : 1;
    else
        // do unsigned compare function
        return UnsignedCompareB(aSize, a, bSize, b);
}

#if ALG_RSA
//*** ModExpB
// This function is used to do modular exponentiation in support of RSA.
// The most typical uses are: 'c' = 'm'^'e' mod 'n' (RSA encrypt) and
// 'm' = 'c'^'d' mod 'n' (RSA decrypt).  When doing decryption, the 'e' parameter
// of the function will contain the private exponent 'd' instead of the public
// exponent 'e'.
//
// If the results will not fit in the provided buffer,
// an error is returned (CRYPT_ERROR_UNDERFLOW). If the results is smaller
// than the buffer, the results is de-normalized.
//
// This version is intended for use with RSA and requires that 'm' be
// less than 'n'.
//
//  Return Type: TPM_RC
//      TPM_RC_SIZE         number to exponentiate is larger than the modulus
//      TPM_RC_NO_RESULT    result will not fit into the provided buffer
//
TPM_RC
ModExpB(UINT32 cSize,  // IN: the size of the output buffer. It will
                       //     need to be the same size as the modulus
        BYTE* c,       // OUT: the buffer to receive the results
                       //     (c->size must be set to the maximum size
                       //     for the returned value)
        const UINT32 mSize,
        const BYTE*  m,  // IN: number to exponentiate
        const UINT32 eSize,
        const BYTE*  e,  // IN: power
        const UINT32 nSize,
        const BYTE*  n  // IN: modulus
)
{
    CRYPT_INT_MAX(bnC);
    CRYPT_INT_MAX(bnM);
    CRYPT_INT_MAX(bnE);
    CRYPT_INT_MAX(bnN);
    NUMBYTES tSize  = (NUMBYTES)nSize;
    TPM_RC   retVal = TPM_RC_SUCCESS;

    // Convert input parameters
    ExtMath_IntFromBytes(bnM, m, (NUMBYTES)mSize);
    ExtMath_IntFromBytes(bnE, e, (NUMBYTES)eSize);
    ExtMath_IntFromBytes(bnN, n, (NUMBYTES)nSize);

    // Make sure that the output is big enough to hold the result
    // and that 'm' is less than 'n' (the modulus)
    if(cSize < nSize)
        ERROR_EXIT(TPM_RC_NO_RESULT);
    if(ExtMath_UnsignedCmp(bnM, bnN) >= 0)
        ERROR_EXIT(TPM_RC_SIZE);
    ExtMath_ModExp(bnC, bnM, bnE, bnN);
    ExtMath_IntToBytes(bnC, c, &tSize);
Exit:
    return retVal;
}
#endif  // ALG_RSA

//*** DivideB()
// Divide an integer ('n') by an integer ('d') producing a quotient ('q') and
// a remainder ('r'). If 'q' or 'r' is not needed, then the pointer to them
// may be set to NULL.
//
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT         'q' or 'r' is too small to receive the result
//
LIB_EXPORT TPM_RC DivideB(const TPM2B* n,  // IN: numerator
                          const TPM2B* d,  // IN: denominator
                          TPM2B*       q,  // OUT: quotient
                          TPM2B*       r   // OUT: remainder
)
{
    CRYPT_INT_MAX_INITIALIZED(bnN, n);
    CRYPT_INT_MAX_INITIALIZED(bnD, d);
    CRYPT_INT_MAX(bnQ);
    CRYPT_INT_MAX(bnR);
    //
    // Do divide with converted values
    ExtMath_Divide(bnQ, bnR, bnN, bnD);

    // Convert the Crypt_Int* result back to 2B format using the size of the original
    // number
    if(q != NULL)
        if(!TpmMath_IntTo2B(bnQ, q, q->size))
            return TPM_RC_NO_RESULT;
    if(r != NULL)
        if(!TpmMath_IntTo2B(bnR, r, r->size))
            return TPM_RC_NO_RESULT;
    return TPM_RC_SUCCESS;
}

//*** AdjustNumberB()
// Remove/add leading zeros from a number in a TPM2B. Will try to make the number
// by adding or removing leading zeros. If the number is larger than the requested
// size, it will make the number as small as possible. Setting 'requestedSize' to
// zero is equivalent to requesting that the number be normalized.
UINT16
AdjustNumberB(TPM2B* num, UINT16 requestedSize)
{
    BYTE*  from;
    UINT16 i;
    // See if number is already the requested size
    if(num->size == requestedSize)
        return requestedSize;
    from = num->buffer;
    if(num->size > requestedSize)
    {
        // This is a request to shift the number to the left (remove leading zeros)
        // Find the first non-zero byte. Don't look past the point where removing
        // more zeros would make the number smaller than requested, and don't throw
        // away any significant digits.
        for(i = num->size; *from == 0 && i > requestedSize; from++, i--)
            ;
        if(i < num->size)
        {
            num->size = i;
            MemoryCopy(num->buffer, from, i);
        }
    }
    // This is a request to shift the number to the right (add leading zeros)
    else
    {
        MemoryCopy(&num->buffer[requestedSize - num->size], num->buffer, num->size);
        MemorySet(num->buffer, 0, requestedSize - num->size);
        num->size = requestedSize;
    }
    return num->size;
}

//*** ShiftLeft()
// This function shifts a byte buffer (a TPM2B) one byte to the left. That is,
// the most significant bit of the most significant byte is lost.
TPM2B* ShiftLeft(TPM2B* value  // IN/OUT: value to shift and shifted value out
)
{
    UINT16 count  = value->size;
    BYTE*  buffer = value->buffer;
    if(count > 0)
    {
        for(count -= 1; count > 0; buffer++, count--)
        {
            buffer[0] = (buffer[0] << 1) + ((buffer[1] & 0x80) ? 1 : 0);
        }
        *buffer <<= 1;
    }
    return value;
}
