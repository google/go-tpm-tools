/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _TICKET_FP_H_
#define _TICKET_FP_H_

//*** TicketIsSafe()
// This function indicates if producing a ticket is safe.
// It checks if the leading bytes of an input buffer is TPM_GENERATED_VALUE
// or its substring of canonical form.  If so, it is not safe to produce ticket
// for an input buffer claiming to be TPM generated buffer
//  Return Type: BOOL
//      TRUE(1)         safe to produce ticket
//      FALSE(0)        not safe to produce ticket
BOOL TicketIsSafe(TPM2B* buffer);

//*** TicketComputeVerified()
// This function creates a TPMT_TK_VERIFIED ticket.
TPM_RC TicketComputeVerified(
    TPMI_RH_HIERARCHY hierarchy,  // IN: hierarchy constant for ticket
    TPM2B_DIGEST*     digest,     // IN: digest
    TPM2B_NAME*       keyName,    // IN: name of key that signed the values
    TPMT_TK_VERIFIED* ticket      // OUT: verified ticket
);

//*** TicketComputeAuth()
// This function creates a TPMT_TK_AUTH ticket.
TPM_RC TicketComputeAuth(
    TPM_ST            type,            // IN: the type of ticket.
    TPMI_RH_HIERARCHY hierarchy,       // IN: hierarchy constant for ticket
    UINT64            timeout,         // IN: timeout
    BOOL              expiresOnReset,  // IN: flag to indicate if ticket expires on
                                       //      TPM Reset
    TPM2B_DIGEST* cpHashA,             // IN: input cpHashA
    TPM2B_NONCE*  policyRef,           // IN: input policyRef
    TPM2B_NAME*   entityName,          // IN: name of entity
    TPMT_TK_AUTH* ticket               // OUT: Created ticket
);

//*** TicketComputeHashCheck()
// This function creates a TPMT_TK_HASHCHECK ticket.
TPM_RC TicketComputeHashCheck(
    TPMI_RH_HIERARCHY  hierarchy,  // IN: hierarchy constant for ticket
    TPM_ALG_ID         hashAlg,    // IN: the hash algorithm for 'digest'
    TPM2B_DIGEST*      digest,     // IN: input digest
    TPMT_TK_HASHCHECK* ticket      // OUT: Created ticket
);

//*** TicketComputeCreation()
// This function creates a TPMT_TK_CREATION ticket.
TPM_RC TicketComputeCreation(TPMI_RH_HIERARCHY hierarchy,  // IN: hierarchy for ticket
                             TPM2B_NAME*       name,       // IN: object name
                             TPM2B_DIGEST*     creation,   // IN: creation hash
                             TPMT_TK_CREATION* ticket      // OUT: created ticket
);

#endif  // _TICKET_FP_H_
