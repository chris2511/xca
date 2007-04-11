/* base definitions */

#ifndef BASE_H
#define BASE_H

#define XCA_TITLE "X Certificate and Key management"

#include <qglobal.h>
#include "local.h"

#ifdef WIN32
#include <windows.h>
#endif

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x00908000L
#define D2I_CLASH(f, a, PP, s) f(a,(const unsigned char **)PP,s)
#define D2I_CLASHT(f, t, a, PP, s) f(t,a,(const unsigned char **)PP,s)
#define HAS_SHA256
#else
#define D2I_CLASH(f, a, PP, s) f(a,(unsigned char **)PP,s)
#define D2I_CLASHT(f, t, a, PP, s) f(t,a,(unsigned char **)PP,s)
#endif

//#define CCHAR(x) ((const char *)(x).toAscii().constData())
#define CCHAR(x) qPrintable(x)
#endif

#define TRACE printf("File: "__FILE__" Func: %s Line: %d\n",__func__, __LINE__);
//#define TRACE
