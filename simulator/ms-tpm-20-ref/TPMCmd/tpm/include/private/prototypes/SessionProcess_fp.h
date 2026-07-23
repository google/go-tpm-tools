/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar  7, 2020  Time: 07:17:48PM
 */

#ifndef _SESSION_PROCESS_FP_H_
#define _SESSION_PROCESS_FP_H_

//*** IsDAExempted()
// This function indicates if a handle is exempted from DA logic.
// A handle is exempted if it is:
//  a) a primary seed handle;
//  b) an object with noDA bit SET;
//  c) an NV Index with TPMA_NV_NO_DA bit SET; or
//  d) a PCR handle.
//
//  Return Type: BOOL
//      TRUE(1)         handle is exempted from DA logic
//      FALSE(0)        handle is not exempted from DA logic
BOOL IsDAExempted(TPM_HANDLE handle  // IN: entity handle
);

//*** ClearCpRpHashes()
void ClearCpRpHashes(COMMAND* command);

//*** CompareNameHash()
// This function computes the name hash and compares it to the nameHash in the
// session data, returning true if they are equal.
BOOL CompareNameHash(COMMAND* command,  // IN: main parsing structure
                     SESSION* session   // IN: session structure with nameHash
);

//*** CompareParametersHash()
// This function computes the parameters hash and compares it to the pHash in
// the session data, returning true if they are equal.
BOOL CompareParametersHash(COMMAND* command,  // IN: main parsing structure
                           SESSION* session   // IN: session structure with pHash
);

#if SEC_CHANNEL_SUPPORT
//*** CompareScKeyNameHash()
// This function computes the secure channel key name hash (from the requester and/or TPM key
// used to establish the secure channel session) and compares it to the scKeyNameHash in the
// session data, returning true if they are equal.
BOOL CompareScKeyNameHash(
    SESSION*    session,     // IN: session structure
    TPM2B_NAME* reqKeyName,  // IN: requester secure channel key name
    TPM2B_NAME* tpmKeyName   // IN: TPM secure channel key name
);
#endif  // SEC_CHANNEL_SUPPORT

//*** ParseSessionBuffer()
// This function is the entry function for command session processing.
// It iterates sessions in session area and reports if the required authorization
// has been properly provided. It also processes audit session and passes the
// information of encryption sessions to parameter encryption module.
//
//  Return Type: TPM_RC
//        various           parsing failure or authorization failure
//
TPM_RC
ParseSessionBuffer(COMMAND* command  // IN: the structure that contains
);

//*** CheckAuthNoSession()
// Function to process a command with no session associated.
// The function makes sure all the handles in the command require no authorization.
//
//  Return Type: TPM_RC
//      TPM_RC_AUTH_MISSING         failure - one or more handles require
//                                  authorization
TPM_RC
CheckAuthNoSession(COMMAND* command  // IN: command parsing structure
);

//*** BuildResponseSession()
// Function to build Session buffer in a response. The authorization data is added
// to the end of command->responseBuffer. The size of the authorization area is
// accumulated in command->authSize.
// When this is called, command->responseBuffer is pointing at the next location
// in the response buffer to be filled. This is where the authorization sessions
// will go, if any. command->parameterSize is the number of bytes that have been
// marshaled as parameters in the output buffer.
TPM_RC
BuildResponseSession(COMMAND* command  // IN: structure that has relevant command
                                       //     information
);

//*** SessionRemoveAssociationToHandle()
// This function deals with the case where an entity associated with an authorization
// is deleted during command processing. The primary use of this is to support
// UndefineSpaceSpecial().
void SessionRemoveAssociationToHandle(TPM_HANDLE handle);

#endif  // _SESSION_PROCESS_FP_H_
