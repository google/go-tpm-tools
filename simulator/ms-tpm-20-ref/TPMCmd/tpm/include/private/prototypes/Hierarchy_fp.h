/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Apr  2, 2019  Time: 04:23:27PM
 */

#ifndef _HIERARCHY_FP_H_
#define _HIERARCHY_FP_H_

//*** HierarchyPreInstall()
// This function performs the initialization functions for the hierarchy
// when the TPM is simulated. This function should not be called if the
// TPM is not in a manufacturing mode at the manufacturer, or in a simulated
// environment.
void HierarchyPreInstall_Init(void);

//*** HierarchyStartup()
// This function is called at TPM2_Startup() to initialize the hierarchy
// related values.
BOOL HierarchyStartup(STARTUP_TYPE type  // IN: start up type
);

//*** HierarchyGetProof()
// This function derives the proof value associated with a hierarchy. It returns a
// buffer containing the proof value.
//
//  Return Type: TPM_RC
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM failed
//                              to derive the Firmware SVN Secret for the requested
//                              SVN.
TPM_RC HierarchyGetProof(TPMI_RH_HIERARCHY hierarchy,  // IN: hierarchy constant
                         TPM2B_PROOF*      proof       // OUT: proof buffer
);

//*** HierarchyGetPrimarySeed()
// This function derives the primary seed of a hierarchy.
//
//  Return Type: TPM_RC
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM failed
//                              to derive the Firmware SVN Secret for the requested
//                              SVN.
TPM_RC HierarchyGetPrimarySeed(TPMI_RH_HIERARCHY hierarchy,  // IN: hierarchy
                               TPM2B_SEED*       seed        // OUT: seed buffer
);

//*** ValidateHierarchy()
// This function ensures a given hierarchy is valid and enabled.
//  Return Type: TPM_RC
//      TPM_RC_HIERARCHY        Hierarchy is disabled
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the given SVN
//                              is greater than the TPM's current SVN.
//      TPM_RC_VALUE            Hierarchy is not valid
TPM_RC ValidateHierarchy(TPMI_RH_HIERARCHY hierarchy  // IN: hierarchy
);

//*** HierarchyIsEnabled()
// This function checks to see if a hierarchy is enabled.
// NOTE: The TPM_RH_NULL hierarchy is always enabled.
//  Return Type: BOOL
//      TRUE(1)         hierarchy is enabled
//      FALSE(0)        hierarchy is disabled
BOOL HierarchyIsEnabled(TPMI_RH_HIERARCHY hierarchy  // IN: hierarchy
);

//*** HierarchyNormalizeHandle
// This function accepts a handle that may or may not be FW- or SVN-bound,
// and returns the base hierarchy to which the handle refers.
TPMI_RH_HIERARCHY HierarchyNormalizeHandle(TPMI_RH_HIERARCHY handle  // IN
);

//*** HierarchyIsFirmwareLimited
// This function accepts a hierarchy handle and returns whether it is firmware-
// limited.
BOOL HierarchyIsFirmwareLimited(TPMI_RH_HIERARCHY handle  // IN
);

//*** HierarchyIsSvnLimited
// This function accepts a hierarchy handle and returns whether it is SVN-
// limited.
BOOL HierarchyIsSvnLimited(TPMI_RH_HIERARCHY handle  // IN
);

#endif  // _HIERARCHY_FP_H_
