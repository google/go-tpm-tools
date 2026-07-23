/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _BN_CONVERT_FP_H_
#define _BN_CONVERT_FP_H_

//*** BnFromBytes()
// This function will convert a big-endian byte array to the internal number
// format. If bn is NULL, then the output is NULL. If bytes is null or the
// required size is 0, then the output is set to zero
LIB_EXPORT bigNum BnFromBytes(bigNum bn, const BYTE* bytes, NUMBYTES nBytes);

//*** BnFrom2B()
// Convert an TPM2B to a BIG_NUM.
// If the input value does not exist, or the output does not exist, or the input
// will not fit into the output the function returns NULL
LIB_EXPORT bigNum BnFrom2B(bigNum       bn,  // OUT:
                           const TPM2B* a2B  // IN: number to convert
);

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
);

//*** BnTo2B()
// Function to convert a BIG_NUM to TPM2B.
// The TPM2B size is set to the requested 'size' which may require padding.
// If 'size' is non-zero and less than required by the value in 'bn' then an error
// is returned. If 'size' is zero, then the TPM2B is assumed to be large enough
// for the data and a2b->size will be adjusted accordingly.
LIB_EXPORT BOOL BnTo2B(bigConst bn,   // IN:
                       TPM2B*   a2B,  // OUT:
                       NUMBYTES size  // IN: the desired size
);
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
    NUMBYTES    nBytesY);

//*** BnPointToBytes()
// This function converts a BIG_POINT into a TPMS_ECC_POINT. A TPMS_ECC_POINT
// contains two TPM2B_ECC_PARAMETER values. The maximum size of the parameters
// is dependent on the maximum EC key size used in an implementation.
// The presumption is that the TPMS_ECC_POINT is large enough to hold 2 TPM2B
// values, each as large as a MAX_ECC_PARAMETER_BYTES
LIB_EXPORT BOOL BnPointToBytes(
    pointConst ecP,  // OUT: the preallocated point structure
    BYTE*      x,
    NUMBYTES*  pBytesX,
    BYTE*      y,
    NUMBYTES*  pBytesY);
#endif  // ALG_ECC

#endif  // _BN_CONVERT_FP_H_
