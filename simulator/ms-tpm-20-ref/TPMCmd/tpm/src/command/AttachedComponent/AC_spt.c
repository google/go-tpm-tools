//** Introduction
// This code in this clause is provided for testing of the TPM's command interface.
// The implementation of Attached Components is not expected to be as shown in this
// code.

//** Includes
#include "Tpm.h"
#include "AC_spt_fp.h"

// This is the simulated AC data. This should be present in an actual implementation.
#if 1

typedef struct
{
    TPMI_RH_AC            ac;
    TPML_AC_CAPABILITIES* acData;

} acCapabilities;

TPML_AC_CAPABILITIES acData0001 = {1, {{TPM_AT_PV1, 0x01234567}}};

acCapabilities       ac[1]      = {{0x0001, &acData0001}};

#  define NUM_AC (sizeof(ac) / sizeof(acCapabilities))

#endif  // 1 The simulated AC data

//** Functions

//*** AcToCapabilities()
// This function returns a pointer to a list of AC capabilities.
TPML_AC_CAPABILITIES* AcToCapabilities(TPMI_RH_AC component  // IN: component
)
{
    UINT32 index;
    //
    for(index = 0; index < NUM_AC; index++)
    {
        if(ac[index].ac == component)
            return ac[index].acData;
    }
    return NULL;
}

//*** AcIsAccessible()
// Function to determine if an AC handle references an actual AC
//  Return Type: BOOL
BOOL AcIsAccessible(TPM_HANDLE acHandle)
{
    // In this implementation, the AC exists if there are some capabilities to go
    // with the handle
    return AcToCapabilities(acHandle) != NULL;
}

//*** AcCapabilitiesGet()
// This function returns a list of capabilities associated with an AC
//  Return Type: TPMI_YES_NO
//      YES         if there are more handles available
//      NO          all the available handles has been returned
TPMI_YES_NO
AcCapabilitiesGet(TPMI_RH_AC            component,      // IN: the component
                  TPM_AT                type,           // IN: start capability type
                  UINT32                count,          // IN: requested number
                  TPML_AC_CAPABILITIES* capabilityList  // OUT: list of handle
)
{
    TPMI_YES_NO more = NO;
    UINT32      i;
    // Get the list of capabilities and their values associated with the AC
    TPML_AC_CAPABILITIES* capabilities;

    VERIFY(HandleGetType(component) == TPM_HT_AC, FATAL_ERROR_ASSERT, NO);
    capabilities = AcToCapabilities(component);

    // Initialize output handle list
    capabilityList->count = 0;
    if(count > MAX_AC_CAPABILITIES)
        count = MAX_AC_CAPABILITIES;

    if(capabilities != NULL)
    {
        // Find the first capability less than or equal to type
        for(i = 0; i < capabilities->count; i++)
        {
            if(capabilities->acCapabilities[i].tag >= type)
            {
                // copy the capabilities until we run out or fill the list
                for(; (capabilityList->count < count) && (i < capabilities->count);
                    i++)
                {
                    capabilityList->acCapabilities[capabilityList->count] =
                        capabilities->acCapabilities[i];
                    capabilityList->count++;
                }
                more = i < capabilities->count;
            }
        }
    }
    return more;
}

//*** AcSendObject()
// Stub to handle sending of an AC object
//  Return Type: TPM_RC
TPM_RC
AcSendObject(TPM_HANDLE      acHandle,  // IN: Handle of AC receiving object
             OBJECT*         object,    // IN: object structure to send
             TPMS_AC_OUTPUT* acDataOut  // OUT: results of operation
)
{
    NOT_REFERENCED(object);
    NOT_REFERENCED(acHandle);
    acDataOut->tag = TPM_AT_ERROR;  // indicate that the response contains an
                                    // error code
    acDataOut->data = TPM_AE_NONE;  // but there is no error.

    return TPM_RC_SUCCESS;
}
