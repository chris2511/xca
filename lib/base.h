/* base definitions */

#ifndef BASE_H
#define BASE_H

#define VER "0.5.0-cvs"

#if QT_VERSION >= 0x030000
#define qt3 1
#endif

#ifdef WIN32
#include <windows.h>
#endif  

#define XCA_TITLE "X Certificate and Key management"

#endif
