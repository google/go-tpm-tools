/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar  7, 2020  Time: 07:06:44PM
 */

#ifndef _COMMAND_DISPATCHER_FP_H_
#define _COMMAND_DISPATCHER_FP_H_

//** ParseHandleBuffer()
// This is the table-driven version of the handle buffer unmarshaling code
TPM_RC
ParseHandleBuffer(COMMAND* command);

//** CommandDispatcher()
// Function to unmarshal the command parameters, call the selected action code, and
// marshal the response parameters.
TPM_RC
CommandDispatcher(COMMAND* command);

#endif  // _COMMAND_DISPATCHER_FP_H_
