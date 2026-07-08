/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _ALGORITHM_CAP_FP_H_
#define _ALGORITHM_CAP_FP_H_

//** AlgorithmCapGetImplemented()
// This function is used by TPM2_GetCapability() to return a list of the
// implemented algorithms.
//
//  Return Type: TPMI_YES_NO
//  YES        more algorithms to report
//  NO         no more algorithms to report
TPMI_YES_NO
AlgorithmCapGetImplemented(TPM_ALG_ID algID,  // IN: the starting algorithm ID
                           UINT32     count,  // IN: count of returned algorithms
                           TPML_ALG_PROPERTY* algList  // OUT: algorithm list
);

//** AlgorithmCapGetOneImplemented()
// This function returns whether a single algorithm was implemented, along
// with its properties (if implemented).
BOOL AlgorithmCapGetOneImplemented(
    TPM_ALG_ID         algID,       // IN: the algorithm ID
    TPMS_ALG_PROPERTY* algProperty  // OUT: algorithm properties
);

//** AlgorithmGetImplementedVector()
// This function returns the bit vector of the implemented algorithms.
LIB_EXPORT
void AlgorithmGetImplementedVector(
    ALGORITHM_VECTOR* implemented  // OUT: the implemented bits are SET
);

#endif  // _ALGORITHM_CAP_FP_H_
