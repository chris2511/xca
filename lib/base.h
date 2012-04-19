/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __BASE_H
#define __BASE_H

#define QT_NO_CAST_TO_ASCII 1
#define XCA_TITLE "X Certificate and Key management"

#include <QtCore/qglobal.h>
#include "local.h"

#ifdef WIN32
#include <windows.h>
#endif

#include <openssl/opensslv.h>

#define CCHAR(x) qPrintable(x)
#endif

#define C_FILE ((strrchr(__FILE__, '/') ? : __FILE__- 1) + 1)
#define TRACE fprintf(stderr, "File: %s Func: %s Line: %d\n", C_FILE, __func__, __LINE__);

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define MIN(a,b) ((a)<(b)) ? (a) : (b)
