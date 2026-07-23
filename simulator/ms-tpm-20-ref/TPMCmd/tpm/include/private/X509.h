//** Introduction
// This file contains the macro and structure definitions for the X509 commands and
// functions.

#ifndef _X509_H_
#define _X509_H_

//** Includes

#include "Tpm.h"
#include "TpmASN1.h"

//** Defined Constants

//*** X509 Application-specific types
#define X509_SELECTION         0xA0
#define X509_ISSUER_UNIQUE_ID  0xA1
#define X509_SUBJECT_UNIQUE_ID 0xA2
#define X509_EXTENSIONS        0xA3

// These defines give the order in which values appear in the TBScertificate
// of an x.509 certificate. These values are used to index into an array of
//
#define ENCODED_SIZE_REF       0
#define VERSION_REF            (ENCODED_SIZE_REF + 1)
#define SERIAL_NUMBER_REF      (VERSION_REF + 1)
#define SIGNATURE_REF          (SERIAL_NUMBER_REF + 1)
#define ISSUER_REF             (SIGNATURE_REF + 1)
#define VALIDITY_REF           (ISSUER_REF + 1)
#define SUBJECT_KEY_REF        (VALIDITY_REF + 1)
#define SUBJECT_PUBLIC_KEY_REF (SUBJECT_KEY_REF + 1)
#define EXTENSIONS_REF         (SUBJECT_PUBLIC_KEY_REF + 1)
#define REF_COUNT              (EXTENSIONS_REF + 1)

//** Structures

// Used to access the fields of a TBSsignature some of which are in the in_CertifyX509
// structure and some of which are in the out_CertifyX509 structure.
typedef struct stringRef
{
    BYTE* buf;
    INT16 len;
} stringRef;

// This is defined to avoid bit by bit comparisons within a UINT32
typedef union x509KeyUsageUnion
{
    TPMA_X509_KEY_USAGE x509;
    UINT32              integer;
} x509KeyUsageUnion;

//** Global X509 Constants
// These values are instanced by X509_spt.c and referenced by other X509-related
// files.

// This is the DER-encoded value for the Key Usage OID  (2.5.29.15). This is the
// full OID, not just the numeric value
#define OID_KEY_USAGE_EXTENSION_VALUE 0x06, 0x03, 0x55, 0x1D, 0x0F
MAKE_OID(_KEY_USAGE_EXTENSION);

// This is the DER-encoded value for the TCG-defined TPMA_OBJECT OID
// (2.23.133.10.1.1.1)
#define OID_TCG_TPMA_OBJECT_VALUE 0x06, 0x07, 0x67, 0x81, 0x05, 0x0a, 0x01, 0x01, 0x01
MAKE_OID(_TCG_TPMA_OBJECT);

#ifdef _X509_SPT_
// If a bit is SET in KEY_USAGE_SIGN is also SET in keyUsage then
// the associated key has to have 'sign' SET.
const x509KeyUsageUnion KEY_USAGE_SIGN = {TPMA_X509_KEY_USAGE_INITIALIZER(
    /* bits_at_0        */ 0,
    /* decipheronly    */ 0,
    /* encipheronly   */ 0,
    /* crlsign          */ 1,
    /* keycertsign     */ 1,
    /* keyagreement   */ 0,
    /* dataencipherment */ 0,
    /* keyencipherment */ 0,
    /* nonrepudiation */ 0,
    /* digitalsignature */ 1)};
// If a bit is SET in KEY_USAGE_DECRYPT is also SET in keyUsage then
// the associated key has to have 'decrypt' SET.
const x509KeyUsageUnion KEY_USAGE_DECRYPT = {TPMA_X509_KEY_USAGE_INITIALIZER(
    /* bits_at_0        */ 0,
    /* decipheronly    */ 1,
    /* encipheronly   */ 1,
    /* crlsign          */ 0,
    /* keycertsign     */ 0,
    /* keyagreement   */ 1,
    /* dataencipherment */ 1,
    /* keyencipherment */ 1,
    /* nonrepudiation */ 0,
    /* digitalsignature */ 0)};
#else
extern x509KeyUsageUnion KEY_USAGE_SIGN;
extern x509KeyUsageUnion KEY_USAGE_DECRYPT;
#endif

#endif  // _X509_H_
