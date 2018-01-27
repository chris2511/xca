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

const char *version_str(bool html)
{
	if (!COMMITHASH[0]) {
		return html ? "<b>" PACKAGE_VERSION "</b>" :
				PACKAGE_VERSION;
	}
	return html ?
		"<b>" PACKAGE_VERSION "+dev</b><br/>"
			"commit: <b>" COMMITHASH "</b>" :
		PACKAGE_VERSION "+dev\n"
			"commit: " COMMITHASH;
}
