#ifndef _TPM_MATH_FP_H_
#define _TPM_MATH_FP_H_

//*** TpmMath_IntFrom2B()
// Convert an TPM2B to a Crypt_Int.
// If the input value does not exist, or the output does not exist, or the input
// will not fit into the output the function returns NULL
LIB_EXPORT Crypt_Int* TpmMath_IntFrom2B(Crypt_Int*   value,  // OUT:
                                        const TPM2B* a2B     // IN: number to convert
);

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
);

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
LIB_EXPORT BOOL TpmMath_GetRandomBits(
    BYTE*       pBuffer,  // OUT: buffer to set
    size_t      bits,     // IN: number of bits to generate (see remarks)
    RAND_STATE* rand      // IN: random engine
);

//*** TpmMath_GetRandomInteger
// This function generates a random integer with the requested number of bits.
// Except for size, no range checking is performed.
// The maximum size that can be created is LARGEST_NUMBER + 64 bits.
// if either more bits, or the Crypt_Int* is too small to contain the requested bits
// the TPM enters failure mode and this function returns FALSE.
LIB_EXPORT BOOL TpmMath_GetRandomInteger(Crypt_Int* bn,  // OUT: integer buffer to set
                                         size_t     bits,  // IN: size of output,
                                         RAND_STATE* rand  // IN: random engine
);

//*** TpmMath_GetRandomInRange()
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
    Crypt_Int*       dest,   // OUT: integer buffer to set
    const Crypt_Int* limit,  // IN: limit (see remarks)
    RAND_STATE*      rand    // IN: random engine
);

#endif  //_TPM_MATH_FP_H_