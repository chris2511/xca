/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pass_info.h"

pass_info::pass_info(const QString &t, const QString &d, QWidget *w)
{
	title = t;
	description = d;
	widget = w;
	type = tr("Password");
	pixmap = QString(":keyImg");
	result = pw_ok;
}

void pass_info::setPin()
{
	type = tr("PIN");
	pixmap = QString(":scardImg");
}
