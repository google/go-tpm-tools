/********************************************************************************/
/*										*/
/*		Splice the OpenSSL() library into the TPM code.    		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: TpmToOsslSym.h 1311 2018-08-23 21:39:29Z kgoldman $		*/
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

#ifndef TPMTOOSSLSYM_H
#define TPMTOOSSLSYM_H

/* B.2.2.2. TpmToOsslSym.h */
/* B.2.2.2.1. Introduction */
/* This header file is used to splice the OpenSSL() library into the TPM code. */
/* The support required of a library are a hash module, a block cipher module and portions of a big
   number library. */
#ifndef _TPM_TO_OSSL_SYM_H_
#define _TPM_TO_OSSL_SYM_H_
#if SYM_LIB == OSSL
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/bn.h>
#include <openssl/ossl_typ.h>
/* B.2.2.3.2. Links to the OpenSSL AES code */
#if ALG_SM4
#error "SM4 is not available"
#endif
#if ALG_CAMELLIA
#error "Camellia is not available"
#endif
/*     Define the order of parameters to the library functions that do block encryption and
       decryption. */
typedef void(*TpmCryptSetSymKeyCall_t)(
				       const BYTE  *in,
				       BYTE        *out,
				       void *keySchedule
				       );
/* The Crypt functions that call the block encryption function use the parameters in the order: */
/* a) keySchedule */
/* b) in buffer */
/* c) out buffer Since open SSL uses the order in encryptoCall_t above, need to swizzle the values
   to the order required by the library. */
#define SWIZZLE(keySchedule, in, out)					\
    (const BYTE *)(in), (BYTE *)(out), (void *)(keySchedule)
/*       Macros to set up the encryption/decryption key schedules */
/* AES: */
#define TpmCryptSetEncryptKeyAES(key, keySizeInBits, schedule)		\
    AES_set_encrypt_key((key), (keySizeInBits), (tpmKeyScheduleAES *)(schedule))
#define TpmCryptSetDecryptKeyAES(key, keySizeInBits, schedule)		\
    AES_set_decrypt_key((key), (keySizeInBits), (tpmKeyScheduleAES *)(schedule))
/*       TDES: */
#define TpmCryptSetEncryptKeyTDES(key, keySizeInBits, schedule)		\
    TDES_set_encrypt_key((key), (keySizeInBits), (tpmKeyScheduleTDES *)(schedule))
#define TpmCryptSetDecryptKeyTDES(key, keySizeInBits, schedule)		\
    TDES_set_encrypt_key((key), (keySizeInBits), (tpmKeyScheduleTDES *)(schedule))
/*       Macros to alias encryption calls to specific algorithms. This should be used
	 sparingly. Currently, only used by CryptRand.c */
/* When using these calls, to call the AES block encryption code, the caller should use:
   TpmCryptEncryptAES(SWIZZLE(keySchedule, in, out)); */
#define TpmCryptEncryptAES          AES_encrypt
#define TpmCryptDecryptAES          AES_decrypt
#define tpmKeyScheduleAES           AES_KEY
#define TpmCryptEncryptTDES         TDES_encrypt
#define TpmCryptDecryptTDES         TDES_decrypt
#define tpmKeyScheduleTDES          DES_key_schedule
typedef union tpmCryptKeySchedule_t tpmCryptKeySchedule_t;
#if ALG_TDES
#include "TpmToOsslDesSupport_fp.h"
#endif
/* This definition would change if there were something to report */
#define SymLibSimulationEnd()
#endif // SYM_LIB == OSSL
#endif // _TPM_TO_OSSL_SYM_H_


#endif
