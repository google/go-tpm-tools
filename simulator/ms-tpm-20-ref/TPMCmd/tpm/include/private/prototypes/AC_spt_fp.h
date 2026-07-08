/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar  4, 2020  Time: 02:36:44PM
 */

#ifndef _AC_SPT_FP_H_
#define _AC_SPT_FP_H_

//*** AcToCapabilities()
// This function returns a pointer to a list of AC capabilities.
TPML_AC_CAPABILITIES* AcToCapabilities(TPMI_RH_AC component  // IN: component
);

//*** AcIsAccessible()
// Function to determine if an AC handle references an actual AC
//  Return Type: BOOL
BOOL AcIsAccessible(TPM_HANDLE acHandle);

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
);

//*** AcSendObject()
// Stub to handle sending of an AC object
//  Return Type: TPM_RC
TPM_RC
AcSendObject(TPM_HANDLE      acHandle,  // IN: Handle of AC receiving object
             OBJECT*         object,    // IN: object structure to send
             TPMS_AC_OUTPUT* acDataOut  // OUT: results of operation
);

#endif  // _AC_SPT_FP_H_
