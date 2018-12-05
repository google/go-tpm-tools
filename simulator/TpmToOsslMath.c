/********************************************************************************/
/*										*/
/*			 TPM to OpenSSL BigNum Shim Layer			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: TpmToOsslMath.c 1314 2018-08-28 14:25:12Z kgoldman $		*/
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

/* B.2.3.2. TpmToOsslMath.c */
/* B.2.3.2.1. Introduction */
/* This file contains the math functions that are not implemented in the BnMath() library
   (yet). These math functions will call the OpenSSL() library to execute the operations. There is a
   difference between the internal format and the OpenSSL() format. To call the OpenSSL() function,
   a BIGNUM structure is created for each passed variable. The sizes in the bignum_t are copied and
   the d pointer in the BIGNUM is set to point to the d parameter of the bignum_t. On return,
   SetSizeOsslToTpm() is used for each returned variable to make sure that the pointers are not
   changed. The size of the returned BIGGNUM is copied to bignum_t. */
/* B.2.3.2.2. Includes and Defines */
#include "Tpm.h"
#if MATH_LIB == OSSL
#include "TpmToOsslMath_fp.h"
/* B.2.3.2.3.1. OsslToTpmBn() */
/* This function converts an OpenSSL() BIGNUM to a TPM bignum. In this implementation it is assumed
   that OpenSSL() used the same format for a big number as does the TPM -- an array of native-endian
   words in little-endian order. */
/* If the array allocated for the OpenSSL() BIGNUM is not the space within the TPM bignum, then the
   data is copied. Otherwise, just the size field of the BIGNUM is copied. */
void
OsslToTpmBn(
	    bigNum          bn,
	    BIGNUM          *osslBn
	    )
{
    unsigned char buffer[LARGEST_NUMBER + 1];
    int buffer_len;

    if(bn != NULL)
	{
	    pAssert(BN_num_bytes(osslBn) >= 0);
	    pAssert(sizeof(buffer) >= (size_t)BN_num_bytes(osslBn));
	    buffer_len = BN_bn2bin(osslBn, buffer);	/* ossl to bin */
	    BnFromBytes(bn, buffer, buffer_len);	/* bin to TPM */
	}
}
/* B.2.3.2.3.2.	BigInitialized() */
/* This function initializes an OSSL BIGNUM from a TPM bignum. */
BIGNUM *
BigInitialized(
	       bigConst            initializer
	       )
{
    BIGNUM *toInit = NULL;
    unsigned char buffer[LARGEST_NUMBER + 1];
    NUMBYTES buffer_len = (NUMBYTES )sizeof(buffer);
    
    if (initializer == NULL) {
	return NULL;
    }
    BnToBytes(initializer, buffer, &buffer_len);	/* TPM to bin */
    toInit = BN_bin2bn(buffer, buffer_len, NULL);	/* bin to ossl */
    return toInit;
}

#ifndef OSSL_DEBUG
#   define BIGNUM_PRINT(label, bn, eol)
#   define DEBUG_PRINT(x)
#else
#   define DEBUG_PRINT(x)   printf("%s", x)
#   define BIGNUM_PRINT(label, bn, eol) BIGNUM_print((label), (bn), (eol))
static
void BIGNUM_print(
		  const char      *label,
		  const BIGNUM    *a,
		  BOOL             eol
		  )
{
    BN_ULONG        *d;
    int              i;
    int              notZero = FALSE;
    if(label != NULL)
	printf("%s", label);
    if(a == NULL)
	{
	    printf("NULL");
	    goto done;
	}
    if (a->neg)
	printf("-");
    for(i = a->top, d = &a->d[i - 1]; i > 0; i--)
	{
	    int         j;
	    BN_ULONG    l = *d--;
	    for(j = BN_BITS2 - 8; j >= 0; j -= 8)
		{
		    BYTE    b = (BYTE)((l >> j) & 0xFF);
		    notZero = notZero || (b != 0);
		    if(notZero)
			printf("%02x", b);
		}
	    if(!notZero)
		printf("0");
	}
 done:
    if(eol)
	printf("\n");
    return;
}
#endif
#if LIBRARY_COMPATIBILITY_CHECK
void
MathLibraryCompatibilityCheck(
			      void
			      )
{
    OSSL_ENTER();
    BIGNUM          *osslTemp = BN_CTX_get(CTX);
    BN_VAR(tpmTemp, 64 * 8); // allocate some space for a test value
    crypt_uword_t           i;
    TPM2B_TYPE(TEST, 16);
    TPM2B_TEST              test = {{16, {0x0F, 0x0E, 0x0D, 0x0C,
					  0x0B, 0x0A, 0x09, 0x08,
					  0x07, 0x06, 0x05, 0x04,
					  0x03, 0x02, 0x01, 0x00}}};
    // Convert the test TPM2B to a bigNum
    BnFrom2B(tpmTemp, &test.b);
    // Convert the test TPM2B to an OpenSSL BIGNUM
    BN_bin2bn(test.t.buffer, test.t.size, osslTemp);
    // Make sure the values are consistent
    cAssert(osslTemp->top == (int)tpmTemp->size);
    for(i = 0; i < tpmTemp->size; i++)
	cAssert(osslTemp->d[0] == tpmTemp->d[0]);
    OSSL_LEAVE();
}
#endif
/* B.2.3.2.3.2. BnModMult() */
/* Does multiply and divide returning the remainder of the divide. */
LIB_EXPORT BOOL
BnModMult(
	  bigNum              result,
	  bigConst            op1,
	  bigConst            op2,
	  bigConst            modulus
	  )
{
    OSSL_ENTER();
    BIG_INITIALIZED(bnResult, result);
    BIG_INITIALIZED(bnOp1, op1);
    BIG_INITIALIZED(bnOp2, op2);
    BIG_INITIALIZED(bnMod, modulus);
    BIG_VAR(bnTemp, (LARGEST_NUMBER_BITS * 4));
    BOOL                OK;
    pAssert(BnGetAllocated(result) >= BnGetSize(modulus));
    OK = BN_mul(bnTemp, bnOp1, bnOp2, CTX);
    OK = OK && BN_div(NULL, bnResult, bnTemp, bnMod, CTX);
    if(OK)
	{
	    result->size = DIV_UP(BN_num_bytes(bnResult),
                                  sizeof(crypt_uword_t));
	    OsslToTpmBn(result, bnResult);
	}
    BN_free(bnTemp);
    BN_free(bnMod);
    BN_free(bnOp2);
    BN_free(bnOp1);
    BN_free(bnResult);
    OSSL_LEAVE();
    return OK;
}
/* B.2.3.2.3.3. BnMult() */
/* Multiplies two numbers */
LIB_EXPORT BOOL
BnMult(
       bigNum               result,
       bigConst             multiplicand,
       bigConst             multiplier
       )
{
    OSSL_ENTER();
    BN_VAR(temp, (LARGEST_NUMBER_BITS * 2));
    BIG_INITIALIZED(bnTemp, temp);
    BIG_INITIALIZED(bnA, multiplicand);
    BIG_INITIALIZED(bnB, multiplier);
    BOOL                OK;
    pAssert(result->allocated >=
	    (BITS_TO_CRYPT_WORDS(BnSizeInBits(multiplicand)
				 + BnSizeInBits(multiplier))));
    OK = BN_mul(bnTemp, bnA, bnB, CTX);
    if(OK)
	{
	    OsslToTpmBn(temp, bnTemp);
	    BnCopy(result, temp);
	}
    BN_free(bnB);
    BN_free(bnA);
    BN_free(bnTemp);
    OSSL_LEAVE();
    return OK;
}
/* B.2.3.2.3.4. BnDiv() */
/* This function divides two bigNum values. The function returns FALSE if there is an error in the
   operation. */
LIB_EXPORT BOOL
BnDiv(
      bigNum               quotient,
      bigNum               remainder,
      bigConst             dividend,
      bigConst             divisor
      )
{
    OSSL_ENTER();
    BIG_INITIALIZED(bnQ, quotient);
    BIG_INITIALIZED(bnR, remainder);
    BIG_INITIALIZED(bnDend, dividend);
    BIG_INITIALIZED(bnSor, divisor);
    BOOL        OK;
    pAssert(!BnEqualZero(divisor));
    if(BnGetSize(dividend) < BnGetSize(divisor))
	{
	    if(quotient)
		BnSetWord(quotient, 0);
	    if(remainder)
		BnCopy(remainder, dividend);
	    OK = TRUE;
	}
    else
	{
	    pAssert((quotient == NULL)
		    || (quotient->allocated >= (unsigned)(dividend->size
							  - divisor->size)));
	    pAssert((remainder == NULL)
		    || (remainder->allocated >= divisor->size));
	    OK = BN_div(bnQ, bnR, bnDend, bnSor, CTX);
	    if(OK)
		{
		    OsslToTpmBn(quotient, bnQ);
		    OsslToTpmBn(remainder, bnR);
		}
	}
    DEBUG_PRINT("In BnDiv:\n");
    BIGNUM_PRINT("   bnDividend: ", bnDend, TRUE);
    BIGNUM_PRINT("    bnDivisor: ", bnSor, TRUE);
    BIGNUM_PRINT("   bnQuotient: ", bnQ, TRUE);
    BIGNUM_PRINT("  bnRemainder: ", bnR, TRUE);
    BN_free(bnSor);
    BN_free(bnDend);
    BN_free(bnR);
    BN_free(bnQ);
    OSSL_LEAVE();
    return OK;
}

#if ALG_RSA
/* B.2.3.2.3.5. BnGcd() */
/* Get the greatest common divisor of two numbers */
LIB_EXPORT BOOL
BnGcd(
      bigNum      gcd,            // OUT: the common divisor
      bigConst    number1,        // IN:
      bigConst    number2         // IN:
      )
{
    OSSL_ENTER();
    BIG_INITIALIZED(bnGcd, gcd);
    BIG_INITIALIZED(bn1, number1);
    BIG_INITIALIZED(bn2, number2);
    BOOL            OK;
    pAssert(gcd != NULL);
    OK = BN_gcd(bnGcd, bn1, bn2, CTX);
    if(OK)
	{
	    OsslToTpmBn(gcd, bnGcd);
	    gcd->size = DIV_UP(BN_num_bytes(bnGcd), sizeof(crypt_uword_t));
	}
    BN_free(bn2);
    BN_free(bn1);
    BN_free(bnGcd);
    OSSL_LEAVE();
    return OK;
}
/* B.2.3.2.3.6. BnModExp() */
/* Do modular exponentiation using bigNum values. The conversion from a bignum_t to a bigNum is
   trivial as they are based on the same structure */
LIB_EXPORT BOOL
BnModExp(
	 bigNum               result,         // OUT: the result
	 bigConst             number,         // IN: number to exponentiate
	 bigConst             exponent,       // IN:
	 bigConst             modulus         // IN:
	 )
{
    OSSL_ENTER();
    BIG_INITIALIZED(bnResult, result);
    BIG_INITIALIZED(bnN, number);
    BIG_INITIALIZED(bnE, exponent);
    BIG_INITIALIZED(bnM, modulus);
    BOOL            OK;
    //
    OK = BN_mod_exp(bnResult, bnN, bnE, bnM, CTX);
    if(OK)
	{
	    OsslToTpmBn(result, bnResult);
	}
    BN_free(bnM);
    BN_free(bnE);
    BN_free(bnN);
    BN_free(bnResult);
    OSSL_LEAVE();
    return OK;
}
/* B.2.3.2.3.7. BnModInverse() */
/* Modular multiplicative inverse */
LIB_EXPORT BOOL
BnModInverse(
	     bigNum               result,
	     bigConst             number,
	     bigConst             modulus
	     )
{
    OSSL_ENTER();
    BIG_INITIALIZED(bnResult, result);
    BIG_INITIALIZED(bnN, number);
    BIG_INITIALIZED(bnM, modulus);
    BOOL                OK;
    OK = (BN_mod_inverse(bnResult, bnN, bnM, CTX) != NULL);
    if(OK)
	{
	    OsslToTpmBn(result, bnResult);
	}
    BN_free(bnM);
    BN_free(bnN);
    BN_free(bnResult);
    OSSL_LEAVE();
    return OK;
}
#endif // TPM_ALG_RSA

#if ALG_ECC
/* B.2.3.2.3.8. PointFromOssl() */
/* Function to copy the point result from an OSSL function to a bigNum */
static BOOL
PointFromOssl(
	      bigPoint         pOut,      // OUT: resulting point
	      EC_POINT        *pIn,       // IN: the point to return
	      bigCurve         E          // IN: the curve
	      )
{
    BIGNUM         *x = NULL;
    BIGNUM         *y = NULL;
    BOOL            OK;
    BN_CTX_start(E->CTX);
    //
    x = BN_CTX_get(E->CTX);
    y = BN_CTX_get(E->CTX);
    if(y == NULL)
	FAIL(FATAL_ERROR_ALLOCATION);
    // If this returns false, then the point is at infinity
    OK = EC_POINT_get_affine_coordinates_GFp(E->G, pIn, x, y, E->CTX);
    if(OK)
	{
	    OsslToTpmBn(pOut->x, x);
	    OsslToTpmBn(pOut->y, y);
	    BnSetWord(pOut->z, 1);
	}
    else
	BnSetWord(pOut->z, 0);
    BN_CTX_end(E->CTX);
    return OK;
}
/* B.2.3.2.3.9. EcPointInitialized() */
/* Allocate and initialize a point. */
static EC_POINT *
EcPointInitialized(
		   pointConst          initializer,
		   bigCurve            E
		   )
{
    BIG_INITIALIZED(bnX, (initializer != NULL) ? initializer->x : NULL);
    BIG_INITIALIZED(bnY, (initializer != NULL) ? initializer->y : NULL);
    EC_POINT            *P = (initializer != NULL && E != NULL)
			     ? EC_POINT_new(E->G) : NULL;
    pAssert(E != NULL);
    if(P != NULL)
	EC_POINT_set_affine_coordinates_GFp(E->G, P, bnX, bnY, E->CTX);
    BN_free(bnY);
    BN_free(bnX);
    return P;
}
/* B.2.3.2.3.10. BnCurveInitialize() */
/* This function initializes the OpenSSL() group definition */
/* It is a fatal error if groupContext is not provided. */
/* Return Values Meaning */
/* NULL the TPM_ECC_CURVE is not valid */
/* non-NULL points to a structure in groupContext */
bigCurve
BnCurveInitialize(
		  bigCurve          E,           // IN: curve structure to initialize
		  TPM_ECC_CURVE     curveId      // IN: curve identifier
		  )
{
    EC_GROUP                *group = NULL;
    EC_POINT                *P = NULL;
    const ECC_CURVE_DATA    *C = GetCurveData(curveId);
    BN_CTX                  *CTX = NULL;
    BIG_INITIALIZED(bnP, C != NULL ? C->prime : NULL);
    BIG_INITIALIZED(bnA, C != NULL ? C->a : NULL);
    BIG_INITIALIZED(bnB, C != NULL ? C->b : NULL);
    BIG_INITIALIZED(bnX, C != NULL ? C->base.x : NULL);
    BIG_INITIALIZED(bnY, C != NULL ? C->base.y : NULL);
    BIG_INITIALIZED(bnN, C != NULL ? C->order : NULL);
    BIG_INITIALIZED(bnH, C != NULL ? C->h : NULL);
    int                      OK = (C != NULL);
    //
    OK = OK && ((CTX = OsslContextEnter()) != NULL);
    // initialize EC group, associate a generator point and initialize the point
    // from the parameter data
    // Create a group structure
    OK = OK && (group = EC_GROUP_new_curve_GFp(bnP, bnA, bnB, CTX)) != NULL;
    // Allocate a point in the group that will be used in setting the
    // generator. This is not needed after the generator is set.
    OK = OK && ((P = EC_POINT_new(group)) != NULL);
    // Need to use this in case Montgomery method is being used
    OK = OK
	 && EC_POINT_set_affine_coordinates_GFp(group, P, bnX, bnY, CTX);
    // Now set the generator
    OK = OK && EC_GROUP_set_generator(group, P, bnN, bnH);
    if(P != NULL)
	EC_POINT_free(P);
    if(!OK && group != NULL)
	{
	    EC_GROUP_free(group);
	    group = NULL;
	}
    if(!OK && CTX != NULL)
	{
	    OsslContextLeave(CTX);
	    CTX = NULL;
	}
    E->G = group;
    E->CTX = CTX;
    E->C = C;
    BN_free(bnH);
    BN_free(bnN);
    BN_free(bnY);
    BN_free(bnX);
    BN_free(bnB);
    BN_free(bnA);
    BN_free(bnP);
    return OK ? E : NULL;
}
/* B.2.3.2.3.11. BnEccModMult() */
/* This function does a point multiply of the form R = [d]S */
/* Return Values Meaning */
/* FALSE failure in operation; treat as result being point at infinity */
LIB_EXPORT BOOL
BnEccModMult(
	     bigPoint             R,         // OUT: computed point
	     pointConst           S,         // IN: point to multiply by 'd' (optional)
	     bigConst             d,         // IN: scalar for [d]S
	     bigCurve             E
	     )
{
    EC_POINT            *pR = EC_POINT_new(E->G);
    EC_POINT            *pS = EcPointInitialized(S, E);
    BIG_INITIALIZED(bnD, d);
    if(S == NULL)
	EC_POINT_mul(E->G, pR, bnD, NULL, NULL, E->CTX);
    else
	EC_POINT_mul(E->G, pR, NULL, pS, bnD, E->CTX);
    PointFromOssl(R, pR, E);
    EC_POINT_free(pR);
    EC_POINT_free(pS);
    BN_free(bnD);
    return !BnEqualZero(R->z);
}
/* B.2.3.2.3.12. BnEccModMult2() */
/* This function does a point multiply of the form R = [d]G + [u]Q */
/* FALSE	failure in operation; treat as result being point at infinity */
LIB_EXPORT BOOL
BnEccModMult2(
	      bigPoint             R,         // OUT: computed point
	      pointConst           S,         // IN: optional point
	      bigConst             d,         // IN: scalar for [d]S or [d]G
	      pointConst           Q,         // IN: second point
	      bigConst             u,         // IN: second scalar
	      bigCurve             E          // IN: curve
	      )
{
    EC_POINT            *pR = EC_POINT_new(E->G);
    EC_POINT            *pS = EcPointInitialized(S, E);
    BIG_INITIALIZED(bnD, d);
    EC_POINT            *pQ = EcPointInitialized(Q, E);
    BIG_INITIALIZED(bnU, u);
    if(S == NULL || S == (pointConst)&(AccessCurveData(E)->base))
	EC_POINT_mul(E->G, pR, bnD, pQ, bnU, E->CTX);
    else
	{
	    const EC_POINT        *points[2];
	    const BIGNUM          *scalars[2];
	    points[0] = pS;
	    points[1] = pQ;
	    scalars[0] = bnD;
	    scalars[1] = bnU;
	    EC_POINTs_mul(E->G, pR, NULL, 2, points, scalars, E->CTX);
	}
    PointFromOssl(R, pR, E);
    EC_POINT_free(pR);
    EC_POINT_free(pS);
    EC_POINT_free(pQ);
    BN_free(bnD);
    BN_free(bnU);
    return !BnEqualZero(R->z);
}
/* B.2.3.2.4. BnEccAdd() */
/* This function does addition of two points. */
/* Return Values Meaning */
/* FALSE failure in operation; treat as result being point at infinity */
LIB_EXPORT BOOL
BnEccAdd(
	 bigPoint             R,         // OUT: computed point
	 pointConst           S,         // IN: point to multiply by 'd'
	 pointConst           Q,         // IN: second point
	 bigCurve             E          // IN: curve
	 )
{
    EC_POINT            *pR = EC_POINT_new(E->G);
    EC_POINT            *pS = EcPointInitialized(S, E);
    EC_POINT            *pQ = EcPointInitialized(Q, E);
    //
    EC_POINT_add(E->G, pR, pS, pQ, E->CTX);
    PointFromOssl(R, pR, E);
    EC_POINT_free(pR);
    EC_POINT_free(pS);
    EC_POINT_free(pQ);
    return !BnEqualZero(R->z);
}
#endif // TPM_ALG_ECC
#endif // MATHLIB OSSL
