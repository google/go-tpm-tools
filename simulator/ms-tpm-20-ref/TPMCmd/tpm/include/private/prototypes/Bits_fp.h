/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _BITS_FP_H_
#define _BITS_FP_H_

//*** TestBit()
// This function is used to check the setting of a bit in an array of bits.
//  Return Type: BOOL
//      TRUE(1)         bit is set
//      FALSE(0)        bit is not set
BOOL TestBit(unsigned int bitNum,       // IN: number of the bit in 'bArray'
             BYTE*        bArray,       // IN: array containing the bits
             unsigned int bytesInArray  // IN: size in bytes of 'bArray'
);

//*** SetBit()
// This function will set the indicated bit in 'bArray'.
void SetBit(unsigned int bitNum,       // IN: number of the bit in 'bArray'
            BYTE*        bArray,       // IN: array containing the bits
            unsigned int bytesInArray  // IN: size in bytes of 'bArray'
);

//*** ClearBit()
// This function will clear the indicated bit in 'bArray'.
void ClearBit(unsigned int bitNum,       // IN: number of the bit in 'bArray'.
              BYTE*        bArray,       // IN: array containing the bits
              unsigned int bytesInArray  // IN: size in bytes of 'bArray'
);

#endif  // _BITS_FP_H_
