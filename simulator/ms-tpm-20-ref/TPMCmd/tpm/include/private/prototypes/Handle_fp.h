/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _HANDLE_FP_H_
#define _HANDLE_FP_H_

//*** HandleGetType()
// This function returns the type of a handle which is the MSO of the handle.
TPM_HT
HandleGetType(TPM_HANDLE handle  // IN: a handle to be checked
);

//*** NextPermanentHandle()
// This function returns the permanent handle that is equal to the input value or
// is the next higher value. If there is no handle with the input value and there
// is no next higher value, it returns 0:
TPM_HANDLE
NextPermanentHandle(TPM_HANDLE inHandle  // IN: the handle to check
);

//*** PermanentCapGetHandles()
// This function returns a list of the permanent handles of PCR, started from
// 'handle'. If 'handle' is larger than the largest permanent handle, an empty list
// will be returned with 'more' set to NO.
//  Return Type: TPMI_YES_NO
//      YES         if there are more handles available
//      NO          all the available handles has been returned
TPMI_YES_NO
PermanentCapGetHandles(TPM_HANDLE   handle,     // IN: start handle
                       UINT32       count,      // IN: count of returned handles
                       TPML_HANDLE* handleList  // OUT: list of handle
);

//*** PermanentCapGetOneHandle()
// This function returns whether a permanent handle exists.
BOOL PermanentCapGetOneHandle(TPM_HANDLE handle  // IN: handle
);

//*** PermanentHandleGetPolicy()
// This function returns a list of the permanent handles of PCR, started from
// 'handle'. If 'handle' is larger than the largest permanent handle, an empty list
// will be returned with 'more' set to NO.
//  Return Type: TPMI_YES_NO
//      YES         if there are more handles available
//      NO          all the available handles has been returned
TPMI_YES_NO
PermanentHandleGetPolicy(TPM_HANDLE handle,  // IN: start handle
                         UINT32     count,   // IN: max count of returned handles
                         TPML_TAGGED_POLICY* policyList  // OUT: list of handle
);

//*** PermanentHandleGetOnePolicy()
// This function returns a permanent handle's policy, if present.
BOOL PermanentHandleGetOnePolicy(TPM_HANDLE          handle,  // IN: handle
                                 TPMS_TAGGED_POLICY* policy   // OUT: tagged policy
);

#endif  // _HANDLE_FP_H_
