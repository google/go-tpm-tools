/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar  4, 2020  Time: 02:36:44PM
 */

#ifndef _ALGORITHM_TESTS_FP_H_
#define _ALGORITHM_TESTS_FP_H_

#if ENABLE_SELF_TESTS

//*** TestAlgorithm()
// Dispatches to the correct test function for the algorithm or gets a list of
// testable algorithms.
//
// If 'toTest' is not NULL, then the test decisions are based on the algorithm
// selections in 'toTest'. Otherwise, 'g_toTest' is used. When bits are clear in
// 'g_toTest' they will also be cleared 'toTest'.
//
// If there doesn't happen to be a test for the algorithm, its associated bit is
// quietly cleared.
//
// If 'alg' is zero (TPM_ALG_ERROR), then the toTest vector is cleared of any bits
// for which there is no test (i.e. no tests are actually run but the vector is
// cleared).
//
// Note: 'toTest' will only ever have bits set for implemented algorithms but 'alg'
// can be anything.
//  Return Type: TPM_RC
//      TPM_RC_CANCELED     test was canceled
LIB_EXPORT
TPM_RC
TestAlgorithm(TPM_ALG_ID alg, ALGORITHM_VECTOR* toTest);
#endif  // ENABLE_SELF_TESTS

#endif  // _ALGORITHM_TESTS_FP_H_
