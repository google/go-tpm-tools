/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _PROPERTY_CAP_FP_H_
#define _PROPERTY_CAP_FP_H_

//*** TPMCapGetProperties()
// This function is used to get the TPM_PT values. The search of properties will
// start at 'property' and continue until 'propertyList' has as many values as
// will fit, or the last property has been reported, or the list has as many
// values as requested in 'count'.
//  Return Type: TPMI_YES_NO
//  YES        more properties are available
//  NO         no more properties to be reported
TPMI_YES_NO
TPMCapGetProperties(TPM_PT property,  // IN: the starting TPM property
                    UINT32 count,     // IN: maximum number of returned
                                      //     properties
                    TPML_TAGGED_TPM_PROPERTY* propertyList  // OUT: property list
);

//*** TPMCapGetOneProperty()
// This function returns a single TPM property, if present.
BOOL TPMCapGetOneProperty(TPM_PT                pt,       // IN: the TPM property
                          TPMS_TAGGED_PROPERTY* property  // OUT: tagged property
);

#endif  // _PROPERTY_CAP_FP_H_
