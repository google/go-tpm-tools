/*(Auto-generated)
 *  Created by TpmPrototypes 1.00
 *  Date: Oct 24, 2019  Time: 10:38:43AM
 */

#ifndef _ACT_SPT_FP_H_
#define _ACT_SPT_FP_H_

//*** ActStartup()
// This function is called by TPM2_Startup() to initialize the ACT counter values.
BOOL ActStartup(STARTUP_TYPE type);

//*** ActGetSignaled()
// This function returns the state of the signaled flag associated with an ACT.
BOOL ActGetSignaled(TPM_RH actHandle);

//***ActShutdown()
// This function saves the current state of the counters
BOOL ActShutdown(TPM_SU state  //IN: the type of the shutdown.
);

//*** ActIsImplemented()
// This function determines if an ACT is implemented in both the TPM and the platform
// code.
BOOL ActIsImplemented(UINT32 act);

//***ActCounterUpdate()
// This function updates the ACT counter. If the counter already has a pending update,
// it returns TPM_RC_RETRY so that the update can be tried again later.
TPM_RC
ActCounterUpdate(TPM_RH handle,   //IN: the handle of the act
                 UINT32 newValue  //IN: the value to set in the ACT
);

//*** ActGetCapabilityData()
// This function returns the list of ACT data
//  Return Type: TPMI_YES_NO
//      YES             if more ACT data is available
//      NO              if no more ACT data to
TPMI_YES_NO
ActGetCapabilityData(TPM_HANDLE     actHandle,  // IN: the handle for the starting ACT
                     UINT32         maxCount,   // IN: maximum allowed return values
                     TPML_ACT_DATA* actList     // OUT: ACT data list
);

//*** ActGetOneCapability()
// This function returns an ACT's capability, if present.
BOOL ActGetOneCapability(TPM_HANDLE     actHandle,  // IN: the handle for the ACT
                         TPMS_ACT_DATA* actData     // OUT: ACT data
);

#endif  // _ACT_SPT_FP_H_
