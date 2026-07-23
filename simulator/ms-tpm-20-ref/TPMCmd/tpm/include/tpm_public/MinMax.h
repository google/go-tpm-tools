
#ifndef _MIN_MAX_H_
#define _MIN_MAX_H_

#ifndef MAX
#  define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#  define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef SIZEOF_MEMBER
#  define SIZEOF_MEMBER(type, member) sizeof(((type*)0)->member)
#endif

#endif  // _MIN_MAX_H_
