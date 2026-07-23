/*(Auto-generated)
 *  Created by TpmStructures; Version 4.4 Mar 26, 2019
 *  Date: Aug 30, 2019  Time: 02:11:52PM
 */

// The attributes defined in this file are produced by the parser that
// creates the structure definitions from Part 3. The attributes are defined
// in that parser and should track the attributes being tested in
// CommandCodeAttributes.c. Generally, when an attribute is added to this list,
// new code will be needed in CommandCodeAttributes.c to test it.

#ifndef COMMAND_ATTRIBUTES_H
#define COMMAND_ATTRIBUTES_H

typedef UINT16 COMMAND_ATTRIBUTES;
#define ENCRYPT_2      ((COMMAND_ATTRIBUTES)1 << 0)
#define ENCRYPT_4      ((COMMAND_ATTRIBUTES)1 << 1)
#define DECRYPT_2      ((COMMAND_ATTRIBUTES)1 << 2)
#define DECRYPT_4      ((COMMAND_ATTRIBUTES)1 << 3)
#define HANDLE_1_USER  ((COMMAND_ATTRIBUTES)1 << 4)
#define HANDLE_1_ADMIN ((COMMAND_ATTRIBUTES)1 << 5)
#define HANDLE_1_DUP   ((COMMAND_ATTRIBUTES)1 << 6)
#define HANDLE_2_USER  ((COMMAND_ATTRIBUTES)1 << 7)
#define PP_COMMAND     ((COMMAND_ATTRIBUTES)1 << 8)
// Bit 9 is reserved.
#define NO_SESSIONS ((COMMAND_ATTRIBUTES)1 << 10)
#define NV_COMMAND  ((COMMAND_ATTRIBUTES)1 << 11)
#define PP_REQUIRED ((COMMAND_ATTRIBUTES)1 << 12)
#define R_HANDLE    ((COMMAND_ATTRIBUTES)1 << 13)
#define ALLOW_TRIAL ((COMMAND_ATTRIBUTES)1 << 14)
#define RO_DISALLOW (((COMMAND_ATTRIBUTES)1 << 15) * CC_ReadOnlyControl)

#endif  // COMMAND_ATTRIBUTES_H
