/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Aug 30, 2019  Time: 02:11:54PM
 */

#ifndef _CRYPT_PRIME_FP_H_
#define _CRYPT_PRIME_FP_H_

//*** IsPrimeInt()
// This will do a test of a word of up to 32-bits in size.
BOOL IsPrimeInt(uint32_t n);

//*** TpmMath_IsProbablyPrime()
// This function is used when the key sieve is not implemented. This function
// Will try to eliminate some of the obvious things before going on
// to perform MillerRabin as a final verification of primeness.
BOOL TpmMath_IsProbablyPrime(Crypt_Int*  prime,  // IN:
                             RAND_STATE* rand    // IN: the random state just
                             //     in case Miller-Rabin is required
);

//*** MillerRabinRounds()
// Function returns the number of Miller-Rabin rounds necessary to give an
// error probability equal to the security strength of the prime. These values
// are from FIPS 186-3.
UINT32
MillerRabinRounds(UINT32 bits  // IN: Number of bits in the RSA prime
);

//*** MillerRabin()
// This function performs a Miller-Rabin test from FIPS 186-3. It does
// 'iterations' trials on the number. In all likelihood, if the number
// is not prime, the first test fails.
//  Return Type: BOOL
//      TRUE(1)         probably prime
//      FALSE(0)        composite
BOOL MillerRabin(Crypt_Int* bnW, RAND_STATE* rand);
#if ALG_RSA

//*** RsaCheckPrime()
// This will check to see if a number is prime and appropriate for an
// RSA prime.
//
// This has different functionality based on whether we are using key
// sieving or not. If not, the number checked to see if it is divisible by
// the public exponent, then the number is adjusted either up or down
// in order to make it a better candidate. It is then checked for being
// probably prime.
//
// If sieving is used, the number is used to root a sieving process.
//
TPM_RC
RsaCheckPrime(Crypt_Int* prime, UINT32 exponent, RAND_STATE* rand);

//*** TpmRsa_GeneratePrimeForRSA()
// Function to generate a prime of the desired size with the proper attributes
// for an RSA prime.
TPM_RC
TpmRsa_GeneratePrimeForRSA(
    Crypt_Int* prime,      // IN/OUT: points to the BN that will get the
                           //  random value
    UINT32      bits,      // IN: number of bits to get
    UINT32      exponent,  // IN: the exponent
    RAND_STATE* rand       // IN: the random state
);
#endif  // ALG_RSA

#endif  // _CRYPT_PRIME_FP_H_
