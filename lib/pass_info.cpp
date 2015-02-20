/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QString>
#include <QWidget>
#include <QApplication>

#include "pass_info.h"

pass_info::pass_info(QString t, QString d, QWidget *w)
{
	title = t;
	description = d;
	widget = w;
	if (!widget)
		widget = qApp->activeWindow();
	type = tr("Password");
	pixmap = MainWindow::keyImg;
}

void pass_info::setPin()
{
	type = tr("PIN");
	pixmap = MainWindow::scardImg;
}

