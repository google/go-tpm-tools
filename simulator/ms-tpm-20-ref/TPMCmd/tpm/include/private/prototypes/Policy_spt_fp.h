/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar  4, 2020  Time: 02:36:44PM
 */

#ifndef _POLICY_SPT_FP_H_
#define _POLICY_SPT_FP_H_

//** Functions
//*** PolicyParameterChecks()
// This function validates the common parameters of TPM2_PolicySiged()
// and TPM2_PolicySecret(). The common parameters are 'nonceTPM',
// 'expiration', and 'cpHashA'.
TPM_RC
PolicyParameterChecks(SESSION*      session,
                      UINT64        authTimeout,
                      TPM2B_DIGEST* cpHashA,
                      TPM2B_NONCE*  nonce,
                      TPM_RC        blameNonce,
                      TPM_RC        blameCpHash,
                      TPM_RC        blameExpiration);

//*** PolicyContextUpdate()
// Update policy hash
//      Update the policyDigest in policy session by extending policyRef and
//      objectName to it. This will also update the cpHash if it is present.
//
//  Return Type: void
TPM_RC PolicyContextUpdate(
    TPM_CC        commandCode,    // IN: command code
    TPM2B_NAME*   name,           // IN: name of entity
    TPM2B_NONCE*  ref,            // IN: the reference data
    TPM2B_DIGEST* cpHash,         // IN: the cpHash (optional)
    UINT64        policyTimeout,  // IN: the timeout value for the policy
    SESSION*      session         // IN/OUT: policy session to be updated
);

//*** ComputeAuthTimeout()
// This function is used to determine what the authorization timeout value for
// the session should be.
UINT64
ComputeAuthTimeout(SESSION* session,   // IN: the session containing the time
                                       //     values
                   INT32 expiration,   // IN: either the number of seconds from
                                       //     the start of the session or the
                                       //     time in g_timer;
                   TPM2B_NONCE* nonce  // IN: indicator of the time base
);

//*** PolicyDigestClear()
// Function to reset the policyDigest of a session
void PolicyDigestClear(SESSION* session);

//*** PolicySptCheckCondition()
// Checks to see if the condition in the policy is satisfied.
BOOL PolicySptCheckCondition(TPM_EO operation, BYTE* opA, BYTE* opB, UINT16 size);

#endif  // _POLICY_SPT_FP_H_
