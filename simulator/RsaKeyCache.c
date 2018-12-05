/********************************************************************************/
/*										*/
/*			     The RSA key cache 					*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: RsaKeyCache.c 1314 2018-08-28 14:25:12Z kgoldman $		*/
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


/* 10.2.22 RsaKeyCache.c */
/* 10.2.22.2 Includes, Types, Locals, and Defines */
#include "Tpm.h"
#if USE_RSA_KEY_CACHE
#include  <stdio.h>
#include "Platform_fp.h"
#include "RsaKeyCache_fp.h"
#if CRT_FORMAT_RSA == YES
#define CACHE_FILE_NAME "RsaKeyCacheCrt.data"
#else
#define CACHE_FILE_NAME "RsaKeyCacheNoCrt.data"
#endif
typedef struct _RSA_KEY_CACHE_
{
    TPM2B_PUBLIC_KEY_RSA        publicModulus;
    TPM2B_PRIVATE_KEY_RSA       privatePrime;
    privateExponent_t           privateExponent;
} RSA_KEY_CACHE;
/* Determine the number of RSA key sizes for the cache */
#ifdef RSA_KEY_SIZE_BITS_1024
#define RSA_1024    YES
#else
#define RSA_1024    NO
#endif
#ifdef RSA_KEY_SIZE_BITS_2048
#define RSA_2048    YES
#else
#define RSA_2048    NO
#endif
#ifdef RSA_KEY_SIZE_BITS_3072
#define RSA_3072    YES
#else
#define RSA_3072    NO
#endif
#ifdef RSA_KEY_SIZE_BITS_4096
#define RSA_4096    YES
#else
#define RSA_4096    NO
#endif
#define comma
TPMI_RSA_KEY_BITS       SupportedRsaKeySizes[] = {
#if RSA_1024
    1024
#   undef comma
#   define comma ,
#endif
#if RSA_2048
    comma 2048
#   undef comma
#   define comma ,
#endif
#if RSA_3072
    comma 3072
#   undef comma
#   define comma ,
#endif
#if RSA_4096
    comma 4096
#endif
};
#define RSA_KEY_CACHE_ENTRIES (RSA_1024 + RSA_2048 + RSA_3072 + RSA_4096)
/* The key cache holds one entry for each of the supported key sizes */
RSA_KEY_CACHE        s_rsaKeyCache[RSA_KEY_CACHE_ENTRIES];
/* Indicates if the key cache is loaded. It can be loaded and enabled or disabled. */
BOOL                 s_keyCacheLoaded = 0;
/* Indicates if the key cache is enabled */
int                  s_rsaKeyCacheEnabled = FALSE;
/* 10.2.22.2.1 RsaKeyCacheControl() */
/* Used to enable and disable the RSA key cache. */
LIB_EXPORT void
RsaKeyCacheControl(
		   int             state
		   )
{
    s_rsaKeyCacheEnabled = state;
}
/* 10.2.22.2.2 InitializeKeyCache() */
/* This will initialize the key cache and attempt to write it to a file for later use. */
static BOOL
InitializeKeyCache(
		   OBJECT              *rsaKey,            // IN/OUT: The object structure in which
		   //          the key is created.
		   RAND_STATE          *rand               // IN: if not NULL, the deterministic
		   //     RNG state
		   )
{
    int                  index;
    TPM_KEY_BITS         keySave = rsaKey->publicArea.parameters.rsaDetail.keyBits;
    BOOL                 OK = TRUE;
    //
    s_rsaKeyCacheEnabled = FALSE;
    for(index = 0; OK && index < RSA_KEY_CACHE_ENTRIES; index++)
	{
	    rsaKey->publicArea.parameters.rsaDetail.keyBits
		= SupportedRsaKeySizes[index];
	    OK = (CryptRsaGenerateKey(rsaKey, rand) == TPM_RC_SUCCESS);
	    if(OK)
		{
		    s_rsaKeyCache[index].publicModulus = rsaKey->publicArea.unique.rsa;
		    s_rsaKeyCache[index].privatePrime = rsaKey->sensitive.sensitive.rsa;
		    s_rsaKeyCache[index].privateExponent = rsaKey->privateExponent;
		}
	}
    rsaKey->publicArea.parameters.rsaDetail.keyBits = keySave;
    s_keyCacheLoaded = OK;
#if SIMULATION && USE_RSA_KEY_CACHE && USE_KEY_CACHE_FILE
    if(OK)
	{
	    FILE                *cacheFile;
	    const char          *fn = CACHE_FILE_NAME;
#if defined _MSC_VER && 1
	    if(fopen_s(&cacheFile, fn, "w+b") != 0)
#else
		cacheFile = fopen(fn, "w+b");
	    if(NULL == cacheFile)
#endif
		{
		    printf("Can't open %s for write.\n", fn);
		}
	    else
		{
		    fseek(cacheFile, 0, SEEK_SET);
		    if(fwrite(s_rsaKeyCache, 1, sizeof(s_rsaKeyCache), cacheFile)
		       != sizeof(s_rsaKeyCache))
			{
			    printf("Error writing cache to %s.", fn);
			}
		}
	    if(cacheFile)
		fclose(cacheFile);
	}
#endif
    return s_keyCacheLoaded;
}
static BOOL
KeyCacheLoaded(
	       OBJECT              *rsaKey,            // IN/OUT: The object structure in which
	       //          the key is created.
	       RAND_STATE          *rand               // IN: if not NULL, the deterministic
	       //     RNG state
	       )
{
#if SIMULATION && USE_RSA_KEY_CACHE && USE_KEY_CACHE_FILE
    if(!s_keyCacheLoaded)
	{
	    FILE            *cacheFile;
	    const char *     fn = CACHE_FILE_NAME;
#if defined _MSC_VER && 1
	    if(fopen_s(&cacheFile, fn, "r+b") == 0)
#else
		cacheFile = fopen(fn, "r+b");
	    if(NULL != cacheFile)
#endif
		{
		    fseek(cacheFile, 0L, SEEK_END);
		    if(ftell(cacheFile) == sizeof(s_rsaKeyCache))
			{
			    fseek(cacheFile, 0L, SEEK_SET);
			    s_keyCacheLoaded = (
						fread(&s_rsaKeyCache, 1, sizeof(s_rsaKeyCache), cacheFile)
						== sizeof(s_rsaKeyCache));
			}
		    fclose(cacheFile);
		}
	}
#endif
    if(!s_keyCacheLoaded)
	s_rsaKeyCacheEnabled = InitializeKeyCache(rsaKey, rand);
    return s_keyCacheLoaded;
}
BOOL
GetCachedRsaKey(
		OBJECT              *key,
		RAND_STATE          *rand               // IN: if not NULL, the deterministic
		//     RNG state
		)
{
    int                      keyBits = key->publicArea.parameters.rsaDetail.keyBits;
    int                      index;
    //
    if(KeyCacheLoaded(key, rand))
	{
	    for(index = 0; index < RSA_KEY_CACHE_ENTRIES; index++)
		{
		    if((s_rsaKeyCache[index].publicModulus.t.size * 8) == keyBits)
			{
			    key->publicArea.unique.rsa = s_rsaKeyCache[index].publicModulus;
			    key->sensitive.sensitive.rsa = s_rsaKeyCache[index].privatePrime;
			    key->privateExponent = s_rsaKeyCache[index].privateExponent;
			    key->attributes.privateExp = SET;
			    return TRUE;
			}
		}
	    return FALSE;
	}
    return s_keyCacheLoaded;
}
#endif  // defined SIMULATION && defined USE_RSA_KEY_CACHE
