// This header file is used to select the library code that gets included in the
// TPM build.

#ifndef _LIB_SUPPORT_H_
#define _LIB_SUPPORT_H_
// TODO_RENAME_INC_FOLDER: public refers to the TPM_CoreLib public headers
#include <tpm_public/tpm_radix.h>

// Include the options for hashing and symmetric. Defer the load of the math package
// Until the bignum parameters are defined.
#ifndef SYM_LIB
#  error SYM_LIB required
#endif
#ifndef HASH_LIB
#  error HASH_LIB required
#endif

#include LIB_INCLUDE(TpmTo, SYM_LIB, Sym)
#include LIB_INCLUDE(TpmTo, HASH_LIB, Hash)

//TODO: was #undef MIN
//was #undef MAX

#endif  // _LIB_SUPPORT_H_
