/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <qstring.h>
#include <qwidget.h>
#include <qapplication.h>

#include "pass_info.h"

pass_info::pass_info(QString t, QString d, QWidget *w)
{
	title=t;
	description=d;
	widget=w;
	if (!widget)
		widget=qApp->activeWindow();
}

QString pass_info::getTitle()
{
	return title;
}

QString pass_info::getDescription()
{
	return description;
}

QWidget *pass_info::getWidget()
{
	return widget;
}

void pass_info::setTitle(QString t)
{
	title = t;
}

void pass_info::setDescription(QString d)
{
	description = d;
}
void pass_info::setWidget(QWidget *w)
{
	widget = w;
}
