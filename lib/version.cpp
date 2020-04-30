/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 Christian Hohnstaedt.
 *
 * All rights reserved.
 * Compiles much faster than MW_help.cpp
 * and needs to get recompiled every time
 */

#ifndef QMAKE
#include "local.h"
#endif

#ifndef NO_COMMITHASH
#include "commithash.h"
#else
#define COMMITHASH ""
#endif

#ifndef VERSION_ITERATION
#define VERSION PACKAGE_VERSION
#else
#define VERSION PACKAGE_VERSION VERSION_ITERATION
#endif

const char *version_str(bool html)
{
	if (!COMMITHASH[0])
		return html ? "<b>" VERSION "</b>" : VERSION;

	return html ?
		"<b>" VERSION "-dev</b><br/>commit: <b>" COMMITHASH "</b>" :
		VERSION "-dev\ncommit: " COMMITHASH;
}
