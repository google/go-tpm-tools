/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar  7, 2020  Time: 07:19:36PM
 */

#ifndef _ENTITY_FP_H_
#define _ENTITY_FP_H_

//** Functions
//*** EntityGetLoadStatus()
// This function will check that all the handles access loaded entities.
//  Return Type: TPM_RC
//      TPM_RC_HANDLE           handle type does not match
//      TPM_RC_REFERENCE_Hx     entity is not present
//      TPM_RC_HIERARCHY        entity belongs to a disabled hierarchy
//      TPM_RC_OBJECT_MEMORY    handle is an evict object but there is no
//                               space to load it to RAM
TPM_RC
EntityGetLoadStatus(COMMAND* command  // IN/OUT: command parsing structure
);

//*** EntityGetAuthValue()
// This function is used to access the 'authValue' associated with a handle.
// This function assumes that the handle references an entity that is accessible
// and the handle is not for a persistent objects. That is EntityGetLoadStatus()
// should have been called. Also, the accessibility of the authValue should have
// been verified by IsAuthValueAvailable().
//
// This function copies the authorization value of the entity to 'auth'.
// Return Type: UINT16
//      count           number of bytes in the authValue with 0's stripped
UINT16
EntityGetAuthValue(TPMI_DH_ENTITY handle,  // IN: handle of entity
                   TPM2B_AUTH*    auth     // OUT: authValue of the entity
);

//*** EntityGetAuthPolicy()
// This function is used to access the 'authPolicy' associated with a handle.
// This function assumes that the handle references an entity that is accessible
// and the handle is not for a persistent objects. That is EntityGetLoadStatus()
// should have been called. Also, the accessibility of the authPolicy should have
// been verified by IsAuthPolicyAvailable().
//
// This function copies the authorization policy of the entity to 'authPolicy'.
//
//  The return value is the hash algorithm for the policy.
TPMI_ALG_HASH
EntityGetAuthPolicy(TPMI_DH_ENTITY handle,     // IN: handle of entity
                    TPM2B_DIGEST*  authPolicy  // OUT: authPolicy of the entity
);

//*** EntityGetName()
// This function returns the Name associated with a handle.
TPM2B_NAME* EntityGetName(TPMI_DH_ENTITY handle,  // IN: handle of entity
                          TPM2B_NAME*    name     // OUT: name of entity
);

//*** EntityGetHierarchy()
// This function returns the hierarchy handle associated with an entity.
// a) A handle that is a hierarchy handle is associated with itself.
// b) An NV index belongs to TPM_RH_PLATFORM if TPMA_NV_PLATFORMCREATE,
//    is SET, otherwise it belongs to TPM_RH_OWNER
// c) An object handle belongs to its hierarchy.
TPMI_RH_HIERARCHY
EntityGetHierarchy(TPMI_DH_ENTITY handle  // IN :handle of entity
);

#endif  // _ENTITY_FP_H_
