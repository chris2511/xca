/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 Christian Hohnstaedt.
 *
 * All rights reserved.
 * Compiles much faster than MW_help.cpp
 * and needs to get recompiled every time
 */

#include "local.h"

#define VERSION XCA_VERSION

#ifdef GIT_LOCAL_CHANGES
#define COMMITHASH GIT_COMMIT_REV "+local-changes"
#else
#define COMMITHASH GIT_COMMIT_REV
#endif

const char *version_str(bool html)
{
	if (!COMMITHASH[0])
		return html ? "<b>" VERSION "</b>" : VERSION;

	return html ?
		"<b>" VERSION "-dev</b><br/>commit: <b>" COMMITHASH "</b>" :
		VERSION "-dev\ncommit: " COMMITHASH;
}
