/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __BASE_H
#define __BASE_H

#define QT_NO_CAST_TO_ASCII
#define OPENSSL_NO_STDIO

// Disable advertisement for crappy, insecure, non-conformant MS BS _s functions
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

#ifndef PACKAGE_NAME
#define XCA_TITLE "X Certificate and Key management"
#else
#define XCA_TITLE PACKAGE_NAME
#endif

#include <QtGlobal>
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
#if defined(Q_OS_WIN32)
#include <stdlib.h>
#define xhtonl(x) (_byteswap_ulong(x))
#define xntohl(x) (_byteswap_ulong(x))
#else
#define xhtonl(x) (__builtin_bswap32(x))
#define xntohl(x) (__builtin_bswap32(x))
#endif
#else
	# error "What kind of system is this?"
#endif

#define COL_CYAN  "\x1b[0;36m"
#define COL_BLUE  "\x1b[0;94m"
#define COL_GREEN "\x1b[0;92m"
#define COL_LRED  "\x1b[0;91m"
#define COL_YELL  "\x1b[0;33m"
#define COL_RED   "\x1b[0;31m"
#define COL_RESET "\x1b[0m"
#define COL_BOLD  "\x1b[1m"
#define COL_DIM   "\x1b[2m"
#define COL_UNDER "\x1b[4m"

#endif
