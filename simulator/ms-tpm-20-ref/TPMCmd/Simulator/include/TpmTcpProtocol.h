//** Introduction

// TPM commands are communicated as uint8_t streams on a TCP connection.  The TPM
// command protocol is enveloped with the interface protocol described in this
// file. The command is indicated by a uint32 with one of the values below.  Most
// commands take no parameters return no TPM errors.  In these cases the TPM
// interface protocol acknowledges that command processing is completed by returning
// a uint32=0. The command TPM_SIGNAL_HASH_DATA takes a uint32-prepended variable
// length byte array and the interface protocol acknowledges command completion
// with a uint32=0. Most TPM commands are enveloped using the TPM_SEND_COMMAND
// interface command. The parameters are as indicated below.  The interface layer
// also appends a UIN32=0 to the TPM response for regularity.

//** Typedefs and Defines
#ifndef TCP_TPM_PROTOCOL_H
#define TCP_TPM_PROTOCOL_H

//** TPM Commands.
// All commands acknowledge processing by returning a uint32 == 0 except where noted
#define TPM_SIGNAL_POWER_ON      1
#define TPM_SIGNAL_POWER_OFF     2
#define TPM_SIGNAL_PHYS_PRES_ON  3
#define TPM_SIGNAL_PHYS_PRES_OFF 4
#define TPM_SIGNAL_HASH_START    5
#define TPM_SIGNAL_HASH_DATA     6
// {uint32_t BufferSize, uint8_t[BufferSize] Buffer}
#define TPM_SIGNAL_HASH_END 7
#define TPM_SEND_COMMAND    8
// {uint8_t Locality, uint32_t InBufferSize, uint8_t[InBufferSize] InBuffer} ->
//     {uint32_t OutBufferSize, uint8_t[OutBufferSize] OutBuffer}

#define TPM_SIGNAL_CANCEL_ON     9
#define TPM_SIGNAL_CANCEL_OFF    10
#define TPM_SIGNAL_NV_ON         11
#define TPM_SIGNAL_NV_OFF        12
#define TPM_SIGNAL_KEY_CACHE_ON  13
#define TPM_SIGNAL_KEY_CACHE_OFF 14

#define TPM_REMOTE_HANDSHAKE       15
#define TPM_SET_ALTERNATIVE_RESULT 16

#define TPM_SIGNAL_RESET   17
#define TPM_SIGNAL_RESTART 18

#define TPM_SESSION_END 20
#define TPM_STOP        21

#define TPM_GET_COMMAND_RESPONSE_SIZES 25

#define TPM_ACT_GET_SIGNALED 26

#define TPM_TEST_FAILURE_MODE 30

#define TPM_SET_FW_HASH 35
#define TPM_SET_FW_SVN  36

//** Enumerations and Structures
enum TpmEndPointInfo
{
    tpmPlatformAvailable = 0x01,
    tpmUsesTbs           = 0x02,
    tpmInRawMode         = 0x04,
    tpmSupportsPP        = 0x08,

    // Valid only with PlatformAvailable set.
    // System and TPM power control signals (SignalPowerOn/Off) are not supported.
    NoPowerCtl = 0x10,

    // Valid only with tpmPlatformAvailable set.
    // TPM locality cannot be changed.
    NoLocalityCtl = 0x20,

    // Valid only with tpmPlatformAvailable set.
    // NV control signals (SignalNvOn/Off) are not supported.
    NoNvCtl = 0x40,

    // indicates that no force failure mode is available in the protocol
    NoForceFailure = 0x80,

    // indicates Locality 4 Hash indications are not supported
    NoHashDataCtl = 0x100
};

#ifdef _MSC_VER
#  pragma warning(push, 3)
#endif

// Existing RPC interface type definitions retained so that the implementation
// can be re-used
typedef struct in_buffer
{
    unsigned long  BufferSize;
    unsigned char* Buffer;
} _IN_BUFFER;

typedef unsigned char* _OUTPUT_BUFFER;

typedef struct out_buffer
{
    uint32_t       BufferSize;
    _OUTPUT_BUFFER Buffer;
} _OUT_BUFFER;

#ifdef _MSC_VER
#  pragma warning(pop)
#endif

#ifndef WIN32
typedef unsigned long DWORD;
typedef void*         LPVOID;
#endif

#endif
