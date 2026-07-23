//** Introduction
// This file contains the basic conversion functions that will convert TPM2B
// to/from the internal format. The internal format is a bigNum,
//

//** Includes

#include "TpmBigNum.h"

//** Functions

//*** BnFromBytes()
// This function will convert a big-endian byte array to the internal number
// format. If bn is NULL, then the output is NULL. If bytes is null or the
// required size is 0, then the output is set to zero
LIB_EXPORT bigNum BnFromBytes(bigNum bn, const BYTE* bytes, NUMBYTES nBytes)
{
    const BYTE*   pFrom;  // 'p' points to the least significant bytes of source
    BYTE*         pTo;    // points to least significant bytes of destination
    crypt_uword_t size;
    //

    size = (bytes != NULL) ? BYTES_TO_CRYPT_WORDS(nBytes) : 0;

    // If nothing in, nothing out
    if(bn == NULL)
        return NULL;

    // make sure things fit
    pAssert(BnGetAllocated(bn) >= size);

    if(size > 0)
    {
        // Clear the topmost word in case it is not filled with data
        bn->d[size - 1] = 0;
        // Moving the input bytes from the end of the list (LSB) end
        pFrom = bytes + nBytes - 1;
        // To the LS0 of the LSW of the bigNum.
        pTo = (BYTE*)bn->d;
        for(; nBytes != 0; nBytes--)
            *pTo++ = *pFrom--;
        // For a little-endian machine, the conversion is a straight byte
        // reversal. For a big-endian machine, we have to put the words in
        // big-endian byte order
#if BIG_ENDIAN_TPM
        {
            crypt_word_t t;
            for(t = (crypt_word_t)size - 1; t >= 0; t--)
                bn->d[t] = SWAP_CRYPT_WORD(bn->d[t]);
        }
#endif
    }
    BnSetTop(bn, size);
    return bn;
}

//*** BnFrom2B()
// Convert an TPM2B to a BIG_NUM.
// If the input value does not exist, or the output does not exist, or the input
// will not fit into the output the function returns NULL
LIB_EXPORT bigNum BnFrom2B(bigNum       bn,  // OUT:
                           const TPM2B* a2B  // IN: number to convert
)
{
    if(a2B != NULL)
        return BnFromBytes(bn, a2B->buffer, a2B->size);
    // Make sure that the number has an initialized value rather than whatever
    // was there before
    BnSetTop(bn, 0);  // Function accepts NULL
    return NULL;
}

//*** BnToBytes()
// This function converts a BIG_NUM to a byte array. It converts the bigNum to a
// big-endian byte string and sets 'size' to the normalized value. If  'size' is an
// input 0, then the receiving buffer is guaranteed to be large enough for the result
// and the size will be set to the size required for bigNum (leading zeros
// suppressed).
//
// The conversion for a little-endian machine simply requires that all significant
// bytes of the bigNum be reversed. For a big-endian machine, rather than
// unpack each word individually, the bigNum is converted to little-endian words,
// copied, and then converted back to big-endian.
LIB_EXPORT BOOL BnToBytes(bigConst  bn,
                          BYTE*     buffer,
                          NUMBYTES* size  // This the number of bytes that are
                                          // available in the buffer. The result
                                          // should be this big.
)
{
    crypt_uword_t requiredSize;
    BYTE*         pFrom;
    BYTE*         pTo;
    crypt_uword_t count;
    //
    // validate inputs
    pAssert(bn && buffer && size);

    requiredSize = (BnSizeInBits(bn) + 7) / 8;
    if(requiredSize == 0)
    {
        // If the input value is 0, return a byte of zero
        *size   = 1;
        *buffer = 0;
    }
    else
    {
#if BIG_ENDIAN_TPM
        // Copy the constant input value into a modifiable value
        BN_VAR(bnL, LARGEST_NUMBER_BITS * 2);
        BnCopy(bnL, bn);
        // byte swap the words in the local value to make them little-endian
        for(count = 0; count < bnL->size; count++)
            bnL->d[count] = SWAP_CRYPT_WORD(bnL->d[count]);
        bn = (bigConst)bnL;
#endif
        if(*size == 0)
            *size = (NUMBYTES)requiredSize;
        pAssert(requiredSize <= *size);
        // Byte swap the number (not words but the whole value)
        count = *size;
        // Start from the least significant word and offset to the most significant
        // byte which is in some high word
        pFrom = (BYTE*)(&bn->d[0]) + requiredSize - 1;
        pTo   = buffer;

        // If the number of output bytes is larger than the number bytes required
        // for the input number, pad with zeros
        for(count = *size; count > requiredSize; count--)
            *pTo++ = 0;
        // Move the most significant byte at the end of the BigNum to the next most
        // significant byte position of the 2B and repeat for all significant bytes.
        for(; requiredSize > 0; requiredSize--)
            *pTo++ = *pFrom--;
    }
    return TRUE;
}

//*** BnTo2B()
// Function to convert a BIG_NUM to TPM2B.
// The TPM2B size is set to the requested 'size' which may require padding.
// If 'size' is non-zero and less than required by the value in 'bn' then an error
// is returned. If 'size' is zero, then the TPM2B is assumed to be large enough
// for the data and a2b->size will be adjusted accordingly.
LIB_EXPORT BOOL BnTo2B(bigConst bn,   // IN:
                       TPM2B*   a2B,  // OUT:
                       NUMBYTES size  // IN: the desired size
)
{
    // Set the output size
    if(bn && a2B)
    {
        a2B->size = size;
        return BnToBytes(bn, a2B->buffer, &a2B->size);
    }
    return FALSE;
}

#if ALG_ECC

//*** BnPointFromBytes()
// Function to create a BIG_POINT structure from a byte buffer in big-endian order.
// A point is going to be two ECC values in the same buffer. The values are going
// to be the size of the modulus.  They are in modular form.
LIB_EXPORT bn_point_t* BnPointFromBytes(
    bigPoint    ecP,  // OUT: the preallocated point structure
    const BYTE* x,
    NUMBYTES    nBytesX,
    const BYTE* y,
    NUMBYTES    nBytesY)
{
    if(x == NULL || y == NULL)
        return NULL;

    if(NULL != ecP)
    {
        BnFromBytes(ecP->x, x, nBytesX);
        BnFromBytes(ecP->y, y, nBytesY);
        BnSetWord(ecP->z, 1);
    }
    return ecP;
}

//*** BnPointToBytes()
// This function extracts coordinates from a BIG_POINT into
// most-significant-byte-first memory buffers (the native format of
// a TPMS_ECC_POINT.)
// on input the NUMBYTES* parameters indicate the maximum buffer size.
// on output, they represent the amount of significant data in that buffer.
LIB_EXPORT BOOL BnPointToBytes(
    pointConst ecP,  // OUT: the preallocated point structure
    BYTE*      x,
    NUMBYTES*  pBytesX,
    BYTE*      y,
    NUMBYTES*  pBytesY)
{
    pAssert(ecP && x && y && pBytesX && pBytesY);
    pAssert(BnEqualWord(ecP->z, 1));
    BOOL result = BnToBytes(ecP->x, x, pBytesX);
    result      = result && BnToBytes(ecP->y, y, pBytesY);
    // TODO: zeroize on error?
    return result;
}

#endif  // ALG_ECC