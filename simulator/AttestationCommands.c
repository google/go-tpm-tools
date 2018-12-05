/********************************************************************************/
/*										*/
/*			   Attestation Commands  				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: AttestationCommands.c 1259 2018-07-10 19:11:09Z kgoldman $	*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2016 - 2018				*/
/*										*/
/********************************************************************************/

#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "Certify_fp.h"
#if CC_Certify  // Conditional expansion of this file
TPM_RC
TPM2_Certify(
	     Certify_In      *in,            // IN: input parameter list
	     Certify_Out     *out            // OUT: output parameter list
	     )
{
    TPMS_ATTEST             certifyInfo;
    OBJECT                  *signObject = HandleToObject(in->signHandle);
    OBJECT                  *certifiedObject = HandleToObject(in->objectHandle);
    // Input validation
    if(!IsSigningObject(signObject))
	return TPM_RCS_KEY + RC_Certify_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
	return TPM_RCS_SCHEME + RC_Certify_inScheme;
    // Command Output
    // Filling in attest information
    // Common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData,
		     &certifyInfo);
    // Certify specific fields
    certifyInfo.type = TPM_ST_ATTEST_CERTIFY;
    // NOTE: the certified object is not allowed to be TPM_ALG_NULL so
    // 'certifiedObject' will never be NULL
    certifyInfo.attested.certify.name = certifiedObject->name;
    certifyInfo.attested.certify.qualifiedName = certifiedObject->qualifiedName;
    // Sign attestation structure.  A NULL signature will be returned if
    // signHandle is TPM_RH_NULL.  A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned
    // by SignAttestInfo()
    return SignAttestInfo(signObject, &in->inScheme, &certifyInfo,
			  &in->qualifyingData, &out->certifyInfo, &out->signature);
}
#endif // CC_Certify
#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "CertifyCreation_fp.h"
#if CC_CertifyCreation  // Conditional expansion of this file
TPM_RC
TPM2_CertifyCreation(
		     CertifyCreation_In      *in,            // IN: input parameter list
		     CertifyCreation_Out     *out            // OUT: output parameter list
		     )
{
    TPMT_TK_CREATION        ticket;
    TPMS_ATTEST             certifyInfo;
    OBJECT                  *certified = HandleToObject(in->objectHandle);
    OBJECT                  *signObject = HandleToObject(in->signHandle);
    // Input Validation
    if(!IsSigningObject(signObject))
	return TPM_RCS_KEY + RC_CertifyCreation_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
	return TPM_RCS_SCHEME + RC_CertifyCreation_inScheme;
    // CertifyCreation specific input validation
    // Re-compute ticket
    TicketComputeCreation(in->creationTicket.hierarchy, &certified->name,
			  &in->creationHash, &ticket);
    // Compare ticket
    if(!MemoryEqual2B(&ticket.digest.b, &in->creationTicket.digest.b))
	return TPM_RCS_TICKET + RC_CertifyCreation_creationTicket;
    // Command Output
    // Common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData,
		     &certifyInfo);
    // CertifyCreation specific fields
    // Attestation type
    certifyInfo.type = TPM_ST_ATTEST_CREATION;
    certifyInfo.attested.creation.objectName = certified->name;
    // Copy the creationHash
    certifyInfo.attested.creation.creationHash = in->creationHash;
    // Sign attestation structure.  A NULL signature will be returned if
    // signObject is TPM_RH_NULL.  A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned at
    // this point
    return SignAttestInfo(signObject, &in->inScheme, &certifyInfo,
			  &in->qualifyingData, &out->certifyInfo,
			  &out->signature);
}
#endif // CC_CertifyCreation
#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "Quote_fp.h"
#if CC_Quote  // Conditional expansion of this file
TPM_RC
TPM2_Quote(
	   Quote_In        *in,            // IN: input parameter list
	   Quote_Out       *out            // OUT: output parameter list
	   )
{
    TPMI_ALG_HASH            hashAlg;
    TPMS_ATTEST              quoted;
    OBJECT                 *signObject = HandleToObject(in->signHandle);
    // Input Validation
    if(!IsSigningObject(signObject))
	return TPM_RCS_KEY + RC_Quote_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
	return TPM_RCS_SCHEME + RC_Quote_inScheme;
    // Command Output
    // Filling in attest information
    // Common fields
    // FillInAttestInfo may return TPM_RC_SCHEME or TPM_RC_KEY
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData, &quoted);
    // Quote specific fields
    // Attestation type
    quoted.type = TPM_ST_ATTEST_QUOTE;
    // Get hash algorithm in sign scheme.  This hash algorithm is used to
    // compute PCR digest. If there is no algorithm, then the PCR cannot
    // be digested and this command returns TPM_RC_SCHEME
    hashAlg = in->inScheme.details.any.hashAlg;
    if(hashAlg == TPM_ALG_NULL)
	return TPM_RCS_SCHEME + RC_Quote_inScheme;
    // Compute PCR digest
    PCRComputeCurrentDigest(hashAlg, &in->PCRselect,
			    &quoted.attested.quote.pcrDigest);
    // Copy PCR select.  "PCRselect" is modified in PCRComputeCurrentDigest
    // function
    quoted.attested.quote.pcrSelect = in->PCRselect;
    // Sign attestation structure.  A NULL signature will be returned if
    // signObject is NULL.
    return SignAttestInfo(signObject, &in->inScheme, &quoted, &in->qualifyingData,
			  &out->quoted, &out->signature);
}
#endif // CC_Quote
#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "GetSessionAuditDigest_fp.h"
#if CC_GetSessionAuditDigest  // Conditional expansion of this file
TPM_RC
TPM2_GetSessionAuditDigest(
			   GetSessionAuditDigest_In    *in,            // IN: input parameter list
			   GetSessionAuditDigest_Out   *out            // OUT: output parameter list
			   )
{
    SESSION                 *session = SessionGet(in->sessionHandle);
    TPMS_ATTEST              auditInfo;
    OBJECT                 *signObject = HandleToObject(in->signHandle);
    // Input Validation
    if(!IsSigningObject(signObject))
	return TPM_RCS_KEY + RC_GetSessionAuditDigest_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
	return TPM_RCS_SCHEME + RC_GetSessionAuditDigest_inScheme;
    // session must be an audit session
    if(session->attributes.isAudit == CLEAR)
	return TPM_RCS_TYPE + RC_GetSessionAuditDigest_sessionHandle;
    // Command Output
    // Fill in attest information common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData,
		     &auditInfo);
    // SessionAuditDigest specific fields
    auditInfo.type = TPM_ST_ATTEST_SESSION_AUDIT;
    auditInfo.attested.sessionAudit.sessionDigest = session->u2.auditDigest;
    // Exclusive audit session
    auditInfo.attested.sessionAudit.exclusiveSession
	= (g_exclusiveAuditSession == in->sessionHandle);
    // Sign attestation structure.  A NULL signature will be returned if
    // signObject is NULL.
    return SignAttestInfo(signObject, &in->inScheme, &auditInfo,
			  &in->qualifyingData, &out->auditInfo,
			  &out->signature);
}
#endif // CC_GetSessionAuditDigest
#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "GetCommandAuditDigest_fp.h"
#if CC_GetCommandAuditDigest  // Conditional expansion of this file
TPM_RC
TPM2_GetCommandAuditDigest(
			   GetCommandAuditDigest_In    *in,            // IN: input parameter list
			   GetCommandAuditDigest_Out   *out            // OUT: output parameter list
			   )
{
    TPM_RC                  result;
    TPMS_ATTEST             auditInfo;
    OBJECT                 *signObject = HandleToObject(in->signHandle);
    // Input validation
    if(!IsSigningObject(signObject))
	return TPM_RCS_KEY + RC_GetCommandAuditDigest_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
	return TPM_RCS_SCHEME + RC_GetCommandAuditDigest_inScheme;
    // Command Output
    // Fill in attest information common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData,
		     &auditInfo);
    // CommandAuditDigest specific fields
    auditInfo.type = TPM_ST_ATTEST_COMMAND_AUDIT;
    auditInfo.attested.commandAudit.digestAlg = gp.auditHashAlg;
    auditInfo.attested.commandAudit.auditCounter = gp.auditCounter;
    // Copy command audit log
    auditInfo.attested.commandAudit.auditDigest = gr.commandAuditDigest;
    CommandAuditGetDigest(&auditInfo.attested.commandAudit.commandDigest);
    // Sign attestation structure.  A NULL signature will be returned if
    // signHandle is TPM_RH_NULL.  A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned at
    // this point
    result = SignAttestInfo(signObject, &in->inScheme, &auditInfo,
			    &in->qualifyingData, &out->auditInfo,
			    &out->signature);
    // Internal Data Update
    if(result == TPM_RC_SUCCESS && in->signHandle != TPM_RH_NULL)
	// Reset log
	gr.commandAuditDigest.t.size = 0;
    return result;
}
#endif // CC_GetCommandAuditDigest
#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "GetTime_fp.h"
#if CC_GetTime  // Conditional expansion of this file
TPM_RC
TPM2_GetTime(
	     GetTime_In      *in,            // IN: input parameter list
	     GetTime_Out     *out            // OUT: output parameter list
	     )
{
    TPMS_ATTEST             timeInfo;
    OBJECT                 *signObject = HandleToObject(in->signHandle);
    // Input Validation
    if(!IsSigningObject(signObject))
	return TPM_RCS_KEY + RC_GetTime_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
	return TPM_RCS_SCHEME + RC_GetTime_inScheme;
    // Command Output
    // Fill in attest common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData, &timeInfo);
    // GetClock specific fields
    timeInfo.type = TPM_ST_ATTEST_TIME;
    timeInfo.attested.time.time.time = g_time;
    TimeFillInfo(&timeInfo.attested.time.time.clockInfo);
    // Firmware version in plain text
    timeInfo.attested.time.firmwareVersion
	= (((UINT64)gp.firmwareV1) << 32) + gp.firmwareV2;
    // Sign attestation structure.  A NULL signature will be returned if
    // signObject is NULL.
    return SignAttestInfo(signObject, &in->inScheme, &timeInfo, &in->qualifyingData,
			  &out->timeInfo, &out->signature);
}
#endif // CC_GetTime
