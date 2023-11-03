/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "XcaWarningCore.h"
#include "lib/func.h"
#include <QDebug>
#include <QSqlDatabase>

class xcaWarning_i *xcaWarning::gui;

bool xcaWarningCore::print_cmdline(const char *color, const QString &msg)
{
	console_write(stdout, QString("%1:" COL_RESET " %2\n")
				.arg(color).arg(msg).toUtf8());
	return true;
}

void xcaWarningCore::information(const QString &msg)
{
	print_cmdline(COL_CYAN "Information", msg);
}

void xcaWarningCore::warning(const QString &msg)
{
	print_cmdline(COL_RED "Warning", msg);
}

bool xcaWarningCore::yesno(const QString &msg)
{
	return print_cmdline(COL_BLUE "Question", msg);
}

bool xcaWarningCore::okcancel(const QString &msg)
{
	return print_cmdline(COL_BLUE "Question", msg);
}

void xcaWarningCore::sqlerror(QSqlError err)
{
	warning(err.text());
}

void xcaWarningCore::error(const QString &msg)
{
	print_cmdline(COL_RED "Error", msg);
}

void xcaWarningCore::warningv3(const QString &msg, const extList &el)
{
	warning(QString("  " COL_CYAN "%1" COL_RESET "\n%2")
		.arg(msg).arg(el.getConsole(QString("    "))));
}
