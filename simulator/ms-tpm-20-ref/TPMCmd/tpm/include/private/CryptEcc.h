//** Introduction
//
// This file contains structure definitions used for ECC. The structures in this
// file are only used internally. The ECC-related structures that cross the
// public TPM interface are defined in TpmTypes.h
//

// ECC Curve data type decoder ring
// ================================
// | Name                      | Old Name*      | Comments                                                                                   |
// | ------------------------- | -------------- | ------------------------------------------------------------------------------------------ |
// | TPM_ECC_CURVE             |                | 16-bit Curve ID from Part 2 of TCG TPM Spec                                                |
// | TPM_ECC_CURVE_METADATA    | ECC_CURVE      | See description below                                                                      |
// |                           |                |                                                                                            |
// * - if different

// TPM_ECC_CURVE_METADATA
// ======================
// TPM-specific metadata for a particular curve, such as OIDs and signing/kdf
// schemes associated with the curve.
//
// TODO_ECC: Need to remove the curve constants from this structure and replace
// them with a reference to math-lib provided calls. <Once done, add this
// revised comment to the above description> Note: this structure does *NOT*
// include the actual curve constants. The curve constants are no longer in this
// structure because the constants need to be in a format compatible with the
// math library and are retrieved by the `ExtEcc_CurveGet*` family of functions.
//
// Using the math library's constant structure here is not necessary and breaks
// encapsulation.  Using a tpm-specific format means either redundancy (the same
// values exist here and in a math-specific format), or forces the math library
// to adopt a particular format determined by this structure.  Neither outcome
// is as clean as simply leaving the actual constants out of this structure.

#ifndef _CRYPT_ECC_H
#define _CRYPT_ECC_H

//** Structures

#define ECC_BITS (MAX_ECC_KEY_BYTES * 8)
CRYPT_INT_TYPE(ecc, ECC_BITS);

#define CRYPT_ECC_NUM(name) CRYPT_INT_VAR(name, ECC_BITS)

#define CRYPT_ECC_INITIALIZED(name, initializer) \
    CRYPT_INT_INITIALIZED(name, ECC_BITS, initializer)

typedef struct TPM_ECC_CURVE_METADATA
{
    const TPM_ECC_CURVE   curveId;
    const UINT16          keySizeBits;
    const TPMT_KDF_SCHEME kdf;
    const TPMT_ECC_SCHEME sign;
    const BYTE*           OID;
} TPM_ECC_CURVE_METADATA;

//*** Macros
extern const TPM_ECC_CURVE_METADATA eccCurves[ECC_CURVE_COUNT];

#endif
