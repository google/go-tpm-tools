/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/* $Id: SupportLibraryFunctionPrototypes_fp.h 1047 2017-07-20 18:27:34Z kgoldman $ */
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

#ifndef SUPPORT_LIBRARY_FUNCTION_PROTOTYPES_H
#define SUPPORT_LIBRARY_FUNCTION_PROTOTYPES_H

/* This file contains the function prototypes for the functions that need to be present in the
   selected match library. For each function listed, there should be a small stub function. That
   stub provides the interface between the TPM code and the support library. In most cases, the stub
   function will only need to do a format conversion between the TPM big number and the support
   library big number. The TPM big number format was chosen to make this relatively simple and
   fast. */
LIB_EXPORT int SupportLibInit(void);
/* MathLibraryCompatibililtyCheck() This function is only used during development to make sure that
   the library that is being referenced is using the same size of data structures as the TPM. */
void
MathLibraryCompatibilityCheck(
			      void
			      );
/* 5.19.2 BnModMult() */
/* Does multiply op1 * op2 and divide by modulus returning the remainder of the divide. */
LIB_EXPORT BOOL
BnModMult(bigNum result, bigConst op1, bigConst op2, bigConst modulus);
/* 5.19.3 BnMult() */
/* Multiplies two numbers and returns the result */
LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand, bigConst multiplier);
/* 5.19.4 BnDiv() */
/* This function divides two bigNum values. The function returns FALSE if there is an error in the
   operation. */
LIB_EXPORT BOOL BnDiv(bigNum quotient, bigNum remainder,
		      bigConst dividend, bigConst divisor);
/* 5.19.5 BnMod() */
#define BnMod(a, b)     BnDiv(NULL, (a), (a), (b))
/* 5.19.6 BnGcd() */
/* Get the greatest common divisor of two numbers. This function is only needed when the TPM
   implements RSA. */
LIB_EXPORT BOOL BnGcd(bigNum gcd, bigConst number1, bigConst number2);
/* 5.19.7 BnModExp() */
/* Do modular exponentiation using bigNum values. This function is only needed when the TPM
   implements RSA. */
LIB_EXPORT BOOL BnModExp(bigNum result, bigConst number,
			 bigConst exponent, bigConst modulus);
/* 5.19.8 BnModInverse() */
/* Modular multiplicative inverse. This function is only needed when the TPM implements RSA. */
LIB_EXPORT BOOL BnModInverse(bigNum result, bigConst number,
			     bigConst modulus);
/* 5.19.9 BnEccModMult() */
/* This function does a point multiply of the form R = [d]S. A return of FALSE indicates that the
   result was the point at infinity. This function is only needed if the TPM supports ECC. */
LIB_EXPORT BOOL BnEccModMult(bigPoint R, pointConst S, bigConst d, bigCurve E);
/* 5.19.10	BnEccModMult2() */
/* This function does a point multiply of the form R = [d]S + [u]Q. A return of FALSE indicates that
   the result was the point at infinity. This function is only needed if the TPM supports ECC */
LIB_EXPORT BOOL BnEccModMult2(bigPoint R, pointConst S, bigConst d,
			      pointConst Q, bigConst u, bigCurve E);
/* 5.19.11 BnEccAdd() */
/* This function does a point add R = S + Q. A return of FALSE indicates that the result was the
   point at infinity. This function is only needed if the TPM supports ECC. */
LIB_EXPORT BOOL BnEccAdd(bigPoint R, pointConst S, pointConst Q, bigCurve E);
/* 5.19.12 BnCurveInitialize() */
/* This function is used to initialize the pointers of a bnCurve_t structure. The structure is a set
   of pointers to bigNum values. The curve-dependent values are set by a different function. This
   function is only needed if the TPM supports ECC.*/
LIB_EXPORT bigCurve BnCurveInitialize(bigCurve E, TPM_ECC_CURVE curveId);

#endif
