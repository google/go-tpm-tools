/********************************************************************************/
/*										*/
/*		Structure definitions for the self-test				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: SelfTest.h 1311 2018-08-23 21:39:29Z kgoldman $		*/
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

#ifndef SELFTEST_H
#define SELFTEST_H

/* 5.16.1 Introduction */
/* This file contains the structure definitions for the self-test. It also contains macros for use
   when the self-test is implemented. */
/* 5.16.2 Defines */
/* Was typing this a lot */
#define SELF_TEST_FAILURE   FAIL(FATAL_ERROR_SELF_TEST)
/* Use the definition of key sizes to set algorithm values for key size. Need to do this to avoid a
   lot of #ifdefs in the code. Also, define the index for each of the algorithms. */
#if ALG_AES && defined  AES_KEY_SIZE_BITS_128
#   define  AES_128     YES
#   define  AES_128_INDEX   0
#else
#   define  AES_128     NO
#endif
#if ALG_AES && defined  AES_KEY_SIZE_BITS_192
#   define  AES_192     YES
#   define  AES_192_INDEX   (AES_128)
#else
#   define  AES_192     NO
#endif
#if ALG_AES && defined  AES_KEY_SIZE_BITS_256
#   define  AES_256     YES
#   define  AES_256_INDEX   (AES_128 + AES_192)
#else
#   define  AES_256     NO
#endif
#if ALG_SM4 && defined SM4_KEY_SIZE_BITS_128
#   define  SM4_128     YES
#   define  SM4_128_INDEX   (AES_128 + AES_192 + AES_256)
#else
#   define  SM4_128     NO
#endif
#define NUM_SYMS    (AES_128 + AES_192 + AES_256 + SM4_128)
typedef UINT32      SYM_INDEX;
/* These two defines deal with the fact that the TPM_ALG_ID table does not delimit the symmetric
   mode values with a TPM_SYM_MODE_FIRST and TPM_SYM_MODE_LAST */
#define TPM_SYM_MODE_FIRST       ALG_CTR_VALUE
#define TPM_SYM_MODE_LAST        ALG_ECB_VALUE
#define NUM_SYM_MODES   (TPM_SYM_MODE_LAST - TPM_SYM_MODE_FIRST + 1)
/* Define a type to hold a bit vector for the modes. */
#if NUM_SYM_MODES <= 0
#error  "No symmetric modes implemented"
#elif NUM_SYM_MODES <= 8
typedef BYTE    SYM_MODES;
#elif NUM_SYM_MODES <= 16
typedef UINT16  SYM_MODES;
#elif NUM_SYM_MODES <= 32
typedef UINT32  SYM_MODES;
#else
#error "Too many symmetric modes"
#endif
typedef struct {
    const TPM_ALG_ID     alg;                   // the algorithm
    const UINT16         keyBits;               // bits in the key
    const BYTE          *key;                   // The test key
    const UINT32         ivSize;                // block size of the algorithm
    const UINT32         dataInOutSize;         // size  to encrypt/decrypt
    const BYTE          *dataIn;                // data to encrypt
    const BYTE          *dataOut[NUM_SYM_MODES];// data to decrypt
} SYMMETRIC_TEST_VECTOR;
#if ALG_RSA
extern const RSA_KEY        c_rsaTestKey; // This is a constant structure
#endif
#define SYM_TEST_VALUE_REF(value, alg, keyBits, mode)		\
    SIZED_REFERENCE(value##_##alg##keyBits##_##mode)
typedef struct {
    TPM_ALG_ID      alg;
    UINT16          keySizeBits;
} SYM_ALG;
#define SET_ALG(ALG, v)  MemorySetBit((v), ALG, sizeof(v) * 8)
#if ALG_SHA512
#       define  DEFAULT_TEST_HASH               ALG_SHA512_VALUE
#       define  DEFAULT_TEST_DIGEST_SIZE        SHA512_DIGEST_SIZE
#       define  DEFAULT_TEST_HASH_BLOCK_SIZE    SHA512_BLOCK_SIZE
#elif ALG_SHA384
#       define  DEFAULT_TEST_HASH               ALG_SHA384_VALUE
#       define  DEFAULT_TEST_DIGEST_SIZE        SHA384_DIGEST_SIZE
#       define  DEFAULT_TEST_HASH_BLOCK_SIZE    SHA384_BLOCK_SIZE
#elif ALG_SHA256
#       define  DEFAULT_TEST_HASH               ALG_SHA256_VALUE
#       define  DEFAULT_TEST_DIGEST_SIZE        SHA256_DIGEST_SIZE
#       define  DEFAULT_TEST_HASH_BLOCK_SIZE    SHA256_BLOCK_SIZE
#elif ALG_SHA1
#       define  DEFAULT_TEST_HASH               ALG_SHA1_VALUE
#       define  DEFAULT_TEST_DIGEST_SIZE        SHA1_DIGEST_SIZE
#       define  DEFAULT_TEST_HASH_BLOCK_SIZE    SHA1_BLOCK_SIZE
#endif


#endif
