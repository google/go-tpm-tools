//** Description
// This file contains the common code for building a response header, including
// setting the size of the structure. 'command' may be NULL if result is
// not TPM_RC_SUCCESS.

//** Includes and Defines
#include "Tpm.h"
#include "Marshal.h"

//** BuildResponseHeader()
// Adds the response header to the response. It will update command->parameterSize
// to indicate the total size of the response.
void BuildResponseHeader(COMMAND* command,  // IN: main control structure
                         BYTE*    buffer,   // OUT: the output buffer
                         TPM_RC   result    // IN: the response code
)
{
    TPM_ST tag;
    UINT32 size;

    if(result != TPM_RC_SUCCESS)
    {
        tag  = TPM_ST_NO_SESSIONS;
        size = 10;
    }
    else
    {
        tag = command->tag;
        // Compute the overall size of the response
        size = STD_RESPONSE_HEADER + command->handleNum * sizeof(TPM_HANDLE);
        size += command->parameterSize;
        size += (command->tag == TPM_ST_SESSIONS) ? command->authSize + sizeof(UINT32)
                                                  : 0;
    }
    TPM_ST_Marshal(&tag, &buffer, NULL);
    UINT32_Marshal(&size, &buffer, NULL);
    TPM_RC_Marshal(&result, &buffer, NULL);
    if(result == TPM_RC_SUCCESS)
    {
        if(command->handleNum > 0)
            TPM_HANDLE_Marshal(&command->handles[0], &buffer, NULL);
        if(tag == TPM_ST_SESSIONS)
            UINT32_Marshal((UINT32*)&command->parameterSize, &buffer, NULL);
    }
    command->parameterSize = size;
}