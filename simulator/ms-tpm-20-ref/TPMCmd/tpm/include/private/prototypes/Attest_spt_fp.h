/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _ATTEST_SPT_FP_H_
#define _ATTEST_SPT_FP_H_

//***FillInAttestInfo()
// Fill in common fields of TPMS_ATTEST structure.
void FillInAttestInfo(
    TPMI_DH_OBJECT   signHandle,  // IN: handle of signing object
    TPMT_SIG_SCHEME* scheme,      // IN/OUT: scheme to be used for signing
    TPM2B_DATA*      data,        // IN: qualifying data
    TPMS_ATTEST*     attest       // OUT: attest structure
);

//***SignAttestInfo()
// Sign a TPMS_ATTEST structure. If signHandle is TPM_RH_NULL, a null signature
// is returned.
//
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES   'signHandle' references not a signing key
//      TPM_RC_SCHEME       'scheme' is not compatible with 'signHandle' type
//      TPM_RC_VALUE        digest generated for the given 'scheme' is greater than
//                          the modulus of 'signHandle' (for an RSA key);
//                          invalid commit status or failed to generate "r" value
//                          (for an ECC key)
TPM_RC
SignAttestInfo(OBJECT*          signKey,         // IN: sign object
               TPMT_SIG_SCHEME* scheme,          // IN: sign scheme
               TPMS_ATTEST*     certifyInfo,     // IN: the data to be signed
               TPM2B_DATA*      qualifyingData,  // IN: extra data for the signing
                                                 //     process
               TPM2B_ATTEST* attest,             // OUT: marshaled attest blob to be
                                                 //     signed
               TPMT_SIGNATURE* signature         // OUT: signature
);

//*** IsSigningObject()
// Checks to see if the object is OK for signing. This is here rather than in
// Object_spt.c because all the attestation commands use this file but not
// Object_spt.c.
//  Return Type: BOOL
//      TRUE(1)         object may sign
//      FALSE(0)        object may not sign
BOOL IsSigningObject(OBJECT* object  // IN:
);

#endif  // _ATTEST_SPT_FP_H_
