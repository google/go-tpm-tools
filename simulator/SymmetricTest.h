/********************************************************************************/
/*										*/
/*		Structures and data definitions for the symmetric tests		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: SymmetricTest.h 1047 2017-07-20 18:27:34Z kgoldman $		*/
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
/*  (c) Copyright IBM Corp. and others, 2016, 2017				*/
/*										*/
/********************************************************************************/

/* This file contains the structures and data definitions for the symmetric tests. This file
   references the header file that contains the actual test vectors. This organization was chosen so
   that the program that is used to generate the test vector values does not have to also
   re-generate this data. */

/* 10.1.11 SymmetricTest.h */
#ifndef     SELF_TEST_DATA
#error  "This file many only be included in AlgorithmTests.c"
#endif
#ifndef     _SYMMETRIC_TEST_H
#define     _SYMMETRIC_TEST_H
#include    "SymmetricTestData.h"

/* 10.1.11.2 Symmetric Test Structures */

const SYMMETRIC_TEST_VECTOR   c_symTestValues[NUM_SYMS] = {
#undef  COMMA
#if AES_128
    {ALG_AES_VALUE, 128, key_AES128, 16, sizeof(dataIn_AES128), dataIn_AES128,
     {dataOut_AES128_CTR, dataOut_AES128_OFB, dataOut_AES128_CBC,
      dataOut_AES128_CFB, dataOut_AES128_ECB}}
#   define COMMA ,
#endif
#if AES_192
    COMMA
    {ALG_AES_VALUE, 192, key_AES192, 16, sizeof(dataIn_AES192), dataIn_AES192,
     {dataOut_AES192_CTR, dataOut_AES192_OFB, dataOut_AES192_CBC,
      dataOut_AES192_CFB, dataOut_AES192_ECB}}
#   undef   COMMA
#   define COMMA ,
#endif
#if AES_256
    COMMA
    {ALG_AES_VALUE, 256, key_AES256, 16, sizeof(dataIn_AES256), dataIn_AES256,
     {dataOut_AES256_CTR, dataOut_AES256_OFB, dataOut_AES256_CBC,
      dataOut_AES256_CFB, dataOut_AES256_ECB}}
#   undef  COMMA
#   define COMMA ,
#endif
#if SM4_128
    COMMA
    {ALG_SM4_VALUE, 128, key_SM4128, 16, sizeof(dataIn_SM4128), dataIn_SM4128,
     {dataOut_SM4128_CTR, dataOut_SM4128_OFB, dataOut_SM4128_CBC,
      dataOut_SM4128_CFB, dataOut_AES128_ECB}}
#endif
};
#undef COMMA

#endif  // _SYMMETRIC_TEST_H

