// system headers for the simulator, both Windows and Linux

#ifndef _SIMULATOR_SYSHEADERS_H_
#define _SIMULATOR_SYSHEADERS_H_
// include the system headers silencing warnings that occur with /Wall
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef _MSC_VER
#  pragma warning(push, 3)
// C4668 is supposed to be level 4, but this is still necessary to suppress the
// error.  We don't want to suppress it globally because the same error can
// happen in the TPM code and it shouldn't be ignored in those cases because it
// generally means a configuration header is missing.
//
// X is not defined as a preprocessor macro, assuming 0 for #if
#  pragma warning(disable : 4668)
#  include <windows.h>
#  include <winsock.h>
#  pragma warning(pop)
typedef int socklen_t;
#elif defined(__unix__) || defined(__APPLE__)
#  include <unistd.h>
#  include <errno.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/socket.h>
#  include <pthread.h>
// simulate certain windows APIs
#  define ZeroMemory(ptr, sz) (memset((ptr), 0, (sz)))
#  define closesocket(x)      close(x)
#  define INVALID_SOCKET      (-1)
#  define SOCKET_ERROR        (-1)
#  define WSAGetLastError()   (errno)
#  define WSAEADDRINUSE       EADDRINUSE
#  define INT_PTR             intptr_t
typedef int SOCKET;
#  define _strcmpi            strcasecmp
#else
#  error "Unsupported platform."
#endif  // _MSC_VER
#endif  // _SIMULATOR_SYSHEADERS_H_
