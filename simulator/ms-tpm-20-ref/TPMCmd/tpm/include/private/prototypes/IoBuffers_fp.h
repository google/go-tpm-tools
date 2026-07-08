/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _IO_BUFFERS_FP_H_
#define _IO_BUFFERS_FP_H_

//*** MemoryIoBufferAllocationReset()
// This function is used to reset the allocation of buffers.
void MemoryIoBufferAllocationReset(void);

//*** MemoryIoBufferZero()
// Function zeros the action I/O buffer at the end of a command. Calling this is
// not mandatory for proper functionality.
void MemoryIoBufferZero(void);

//*** MemoryGetInBuffer()
// This function returns the address of the buffer into which the
// command parameters will be unmarshaled in preparation for calling
// the command actions.  Returns NULL if not possible.
BYTE* MemoryGetInBuffer(UINT32 size  // Size, in bytes, required for the input
                                     // unmarshaling
);

//*** MemoryGetOutBuffer()
// This function returns the address of the buffer into which the command
// action code places its output values. Returns NULL if not possible.
BYTE* MemoryGetOutBuffer(UINT32 size  // required size of the buffer
);

//*** IsLabelProperlyFormatted()
// This function checks that a label is a null-terminated string.
// NOTE: this function is here because there was no better place for it.
//  Return Type: BOOL
//      TRUE(1)         string is null terminated
//      FALSE(0)        string is not null terminated
BOOL IsLabelProperlyFormatted(TPM2B* x);

#endif  // _IO_BUFFERS_FP_H_
