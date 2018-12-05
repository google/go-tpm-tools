/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: LibSupport.h 809 2016-11-16 18:31:54Z kgoldman $			*/
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
/*  (c) Copyright IBM Corp. and others, 2016					*/
/*										*/
/********************************************************************************/

#ifndef LIBSUPPORT_H
#define LIBSUPPORT_H

/* 5.15	LibSupport.h */

/* This header file is used to select the library code that gets included in the TPM built */
#ifndef _LIB_SUPPORT_H_
#define _LIB_SUPPORT_H_
/* OSSL has a full suite but yields an executable that is much larger than it needs to be. */
#define     OSSL        1
/* LTC has symmetric support, RSA support, and inadequate ECC support */
#define     LTC         2
/*     MSBN only provides math support so should not be used as the hash or symmetric library */
#define     MSBN        3
/*     SYMCRYPT only provides symmetric cryptography so would need to be combined with another
       library that has math support */
#define     SYMCRYPT    4
#if RADIX_BITS == 32
#   define RADIX_BYTES 4
#elif RADIX_BITS == 64
#   define RADIX_BYTES 8
#else
#error  "RADIX_BITS must either be 32 or 64."
#endif
/*     Include the options for hashing If all the optional headers were always part of the
       distribution then it would not be necessary to do the conditional testing before the
       include. )-; */
#if HASH_LIB == OSSL
#  include "TpmToOsslHash.h"
#elif HASH_LIB == LTC
#  include "ltc/TpmToLtcHash.h"
#elif HASH_LIB == SYMCRYPT
#include "symcrypt/TpmToSymcryptHash.h"
#else
#  error "No hash library selected"
#endif
/*     Set the linkage for the selected symmetric library */
#if SYM_LIB == OSSL
#  include "TpmToOsslSym.h"
#elif SYM_LIB == LTC
#  include "ltc/TpmToLtcSym.h"
#elif SYM_LIB == SYMCRYPT
#include "symcrypt/TpmToSymcryptSym.h"
#else
#  error "No symmetric library selected"
#endif
#undef MIN
#undef MIN
/*     Select a big number Library. This uses a define rather than an include so that the header
       will not be included until the required values have been defined. */
#if MATH_LIB == OSSL
#  define MATHLIB_H  "TpmToOsslMath.h"
#elif MATH_LIB == LTC
#  define MATHLIB_H  "ltc/TpmToLtcMath.h"
#elif MATH_LIB == MSBN
#define MATHLIB_H  "msbn/TpmToMsBnMath.h"
#else
#  error "No math library selected"
#endif
#endif // _LIB_SUPPORT_H_


#endif
