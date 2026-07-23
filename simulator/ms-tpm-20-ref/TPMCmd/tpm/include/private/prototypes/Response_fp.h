/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _RESPONSE_FP_H_
#define _RESPONSE_FP_H_

//** BuildResponseHeader()
// Adds the response header to the response. It will update command->parameterSize
// to indicate the total size of the response.
void BuildResponseHeader(COMMAND* command,  // IN: main control structure
                         BYTE*    buffer,   // OUT: the output buffer
                         TPM_RC   result    // IN: the response code
);

#endif  // _RESPONSE_FP_H_
