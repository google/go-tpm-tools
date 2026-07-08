
//** Includes and Data Definitions

// This definition allows this module to "see" the values that are private
// to this module but kept in Global.c for ease of state migration.
#define IO_BUFFER_C
#include "Tpm.h"
#include "IoBuffers_fp.h"

//** Buffers and Functions

// These buffers are set aside to hold command and response values. In this
// implementation, it is not guaranteed that the code will stop accessing
// the s_actionInputBuffer before starting to put values in the
// s_actionOutputBuffer so different buffers are required.
//

//*** MemoryIoBufferAllocationReset()
// This function is used to reset the allocation of buffers.
void MemoryIoBufferAllocationReset(void)
{
    s_actionIoAllocation = 0;
}

//*** MemoryIoBufferZero()
// Function zeros the action I/O buffer at the end of a command. Calling this is
// not mandatory for proper functionality.
void MemoryIoBufferZero(void)
{
    memset(s_actionIoBuffer, 0, s_actionIoAllocation);
}

//*** MemoryGetInBuffer()
// This function returns the address of the buffer into which the
// command parameters will be unmarshaled in preparation for calling
// the command actions.
BYTE* MemoryGetInBuffer(UINT32 size  // Size, in bytes, required for the input
                                     // unmarshaling
)
{
    pAssert_NULL(size <= sizeof(s_actionIoBuffer));
// In this implementation, a static buffer is set aside for the command action
// buffers. The buffer is shared between input and output. This is because
// there is no need to allocate for the worst case input and worst case output
// at the same time.
// Round size up
#define UoM (sizeof(s_actionIoBuffer[0]))
    size = (size + (UoM - 1)) & (UINT32_MAX - (UoM - 1));
    memset(s_actionIoBuffer, 0, size);
    s_actionIoAllocation = size;
    return (BYTE*)&s_actionIoBuffer[0];
}

//*** MemoryGetOutBuffer()
// This function returns the address of the buffer into which the command
// action code places its output values.
BYTE* MemoryGetOutBuffer(UINT32 size  // required size of the buffer
)
{
    BYTE* retVal = (BYTE*)(&s_actionIoBuffer[s_actionIoAllocation / UoM]);
    pAssert_NULL((size + s_actionIoAllocation) < (sizeof(s_actionIoBuffer)));
    // In this implementation, a static buffer is set aside for the command action
    // output buffer.
    memset(retVal, 0, size);
    s_actionIoAllocation += size;
    return retVal;
}

//*** IsLabelProperlyFormatted()
// This function checks that a label is a null-terminated string.
// NOTE: this function is here because there was no better place for it.
//  Return Type: BOOL
//      TRUE(1)         string is null terminated
//      FALSE(0)        string is not null terminated
BOOL IsLabelProperlyFormatted(TPM2B* x)
{
    return (((x)->size == 0) || ((x)->buffer[(x)->size - 1] == 0));
}
