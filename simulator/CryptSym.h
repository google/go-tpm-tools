/********************************************************************************/
/*										*/
/*		Implementation of the symmetric block cipher modes 		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CryptSym.h 1259 2018-07-10 19:11:09Z kgoldman $		*/
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
/*  (c) Copyright IBM Corp. and others, 2017 - 2018				*/
/*										*/
/********************************************************************************/


#ifndef CRYPTSYM_H
#define CRYPTSYM_H

union tpmCryptKeySchedule_t {
#if ALG_AES
    tpmKeyScheduleAES           AES;
#endif
#if ALG_SM4
    tpmKeyScheduleSM4           SM4;
#endif
#if ALG_CAMELLIA
    tpmKeyScheduleCAMELLIA      CAMELLIA;
#endif
#if ALG_TDES
    tpmKeyScheduleTDES          TDES[3];
#endif
#if SYMMETRIC_ALIGNMENT == 8
    uint64_t            alignment;
#else
    uint32_t            alignment;
#endif
};
/* Each block cipher within a library is expected to conform to the same calling conventions with
   three parameters (keySchedule, in, and out) in the same order. That means that all algorithms
   would use the same order of the same parameters. The code is written assuming the (keySchedule,
   in, and out) order. However, if the library uses a different order, the order can be changed with
   a SWIZZLE macro that puts the parameters in the correct order. Note that all algorithms have to
   use the same order and number of parameters because the code to build the calling list is common
   for each call to encrypt or decrypt with the algorithm chosen by setting a function pointer to
   select the algorithm that is used. */
#   define ENCRYPT(keySchedule, in, out)	\
    encrypt(SWIZZLE(keySchedule, in, out))
#   define DECRYPT(keySchedule, in, out)	\
    decrypt(SWIZZLE(keySchedule, in, out))
/* Note that the macros rely on encrypt as local values in the functions that use these
   macros. Those parameters are set by the macro that set the key schedule to be used for the
   call. */
#define ENCRYPT_CASE(ALG)						\
    case TPM_ALG_##ALG:							\
    TpmCryptSetEncryptKey##ALG(key, keySizeInBits, &keySchedule.ALG);	\
    encrypt = (TpmCryptSetSymKeyCall_t)TpmCryptEncrypt##ALG;		\
    break;
#define DECRYPT_CASE(ALG)						\
    case TPM_ALG_##ALG:							\
    TpmCryptSetDecryptKey##ALG(key, keySizeInBits, &keySchedule.ALG);	\
    decrypt = (TpmCryptSetSymKeyCall_t)TpmCryptDecrypt##ALG;		\
    break;
#if ALG_AES
#define ENCRYPT_CASE_AES    ENCRYPT_CASE(AES)
#define DECRYPT_CASE_AES    DECRYPT_CASE(AES)
#else
#define ENCRYPT_CASE_AES
#define DECRYPT_CASE_AES
#endif
#if ALG_SM4
#define ENCRYPT_CASE_SM4    ENCRYPT_CASE(SM4)
#define DECRYPT_CASE_SM4    DECRYPT_CASE(SM4)
#else
#define ENCRYPT_CASE_SM4
#define DECRYPT_CASE_SM4
#endif
#if ALG_CAMELLIA
#define ENCRYPT_CASE_CAMELLIA    ENCRYPT_CASE(CAMELLIA)
#define DECRYPT_CASE_CAMELLIA    DECRYPT_CASE(CAMELLIA)
#else
#define ENCRYPT_CASE_CAMELLIA
#define DECRYPT_CASE_CAMELLIA
#endif
#if ALG_TDES
#define ENCRYPT_CASE_TDES    ENCRYPT_CASE(TDES)
#define DECRYPT_CASE_TDES    DECRYPT_CASE(TDES)
#else
#define ENCRYPT_CASE_TDES
#define DECRYPT_CASE_TDES
#endif
/* For each algorithm the case will either be defined or null. */
#define     SELECT(direction)					    \
    switch(algorithm)						    \
	{								\
	    direction##_CASE_AES					\
	    direction##_CASE_SM4					\
            direction##_CASE_CAMELLIA					\
	    direction##_CASE_TDES					\
	  default:							\
		FAIL(FATAL_ERROR_INTERNAL);				\
	}
#endif
