//** Introduction
// This file contains bit manipulation routines.  They operate on bit arrays.
//
// The 0th bit in the array is the right-most bit in the 0th octet in
// the array.

//** Includes

#include "Tpm.h"

//** Functions

//*** TestBit()
// This function is used to check the setting of a bit in an array of bits.
//  Return Type: BOOL
//      TRUE(1)         bit is set
//      FALSE(0)        bit is not set
BOOL TestBit(unsigned int bitNum,       // IN: number of the bit in 'bArray'
             BYTE*        bArray,       // IN: array containing the bits
             unsigned int bytesInArray  // IN: size in bytes of 'bArray'
)
{
    NOT_REFERENCED(bytesInArray);  // if assertions are disabled.
    pAssert_BOOL(bytesInArray > (bitNum >> 3));
    return ((bArray[bitNum >> 3] & (1 << (bitNum & 7))) != 0);
}

//*** SetBit()
// This function will set the indicated bit in 'bArray'.
void SetBit(unsigned int bitNum,       // IN: number of the bit in 'bArray'
            BYTE*        bArray,       // IN: array containing the bits
            unsigned int bytesInArray  // IN: size in bytes of 'bArray'
)
{
    NOT_REFERENCED(bytesInArray);  // if assertions are disabled.
    // failure will get checked at the end of the command processing, which
    // is soon enough for SetBit use cases.
    pAssert_VOID_OK(bytesInArray > (bitNum >> 3));
    bArray[bitNum >> 3] |= (1 << (bitNum & 7));
}

//*** ClearBit()
// This function will clear the indicated bit in 'bArray'.
void ClearBit(unsigned int bitNum,       // IN: number of the bit in 'bArray'.
              BYTE*        bArray,       // IN: array containing the bits
              unsigned int bytesInArray  // IN: size in bytes of 'bArray'
)
{
    NOT_REFERENCED(bytesInArray);  // if assertions are disabled.
    // failure will get checked at the end of the command processing, which
    // is soon enough for ClearBit use cases. (command auditing, self-test, etc.)
    pAssert_VOID_OK(bytesInArray > (bitNum >> 3));
    bArray[bitNum >> 3] &= ~(1 << (bitNum & 7));
}
