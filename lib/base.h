/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __BASE_H
#define __BASE_H

#define QT_NO_CAST_TO_ASCII 1
#define OPENSSL_NO_STDIO 1

#ifndef PACKAGE_NAME
#define XCA_TITLE "X Certificate and Key management"
#else
#define XCA_TITLE PACKAGE_NAME
#endif

#include <qglobal.h>
#include "local.h"

#define CCHAR(x) qPrintable(x)

#define C_FILE ((strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') : __FILE__- 1) + 1)
#define TRACE qDebug("File: %s Func: %s Line: %d", C_FILE, __func__, __LINE__);

#define nativeSeparator(s) QDir::toNativeSeparators(s)

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define MIN(a,b) ((a)<(b)) ? (a) : (b)

#if Q_BYTE_ORDER == Q_BIG_ENDIAN
#define xhtonl(x) (x)
#define xntohl(x) (x)
#elif Q_BYTE_ORDER == Q_LITTLE_ENDIAN
#define xhtonl(x) (__builtin_bswap32(x))
#define xntohl(x) (__builtin_bswap32(x))
#else
	# error "What kind of system is this?"
#endif

#endif
