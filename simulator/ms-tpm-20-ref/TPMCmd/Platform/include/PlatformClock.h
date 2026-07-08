// This file contains the instance data for the Platform module. It is collected
// in this file so that the state of the module is easier to manage.

#ifndef _PLATFORM_CLOCK_H_
#define _PLATFORM_CLOCK_H_

#ifndef _ARM_
#  ifdef _MSC_VER
#    include <sys/types.h>
#    include <sys/timeb.h>
#  else
#    include <time.h>
#  endif
#endif

#endif  // _PLATFORM_CLOCK_H_
