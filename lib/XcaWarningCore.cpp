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

class xcaWarning_i *xcaWarningCore::gui;

static bool print_cmdline(const char *color, const QString &msg)
{
	console_write(stdout, QString("%1:" COL_RESET " %2\n")
				.arg(color).arg(msg).toUtf8());
	return true;
}

void xcaWarningCore::information(const QString &msg)
{
	if (gui)
		gui->information(msg);
	else
		print_cmdline(COL_CYAN "Information", msg);
}

void xcaWarningCore::warning(const QString &msg)
{
	if (gui)
		gui->warning(msg);
	else
		print_cmdline(COL_RED "Warning", msg);
}

bool xcaWarningCore::yesno(const QString &msg)
{
	return gui ? gui->yesno(msg) :
		print_cmdline(COL_BLUE "Question", msg);
}

bool xcaWarningCore::okcancel(const QString &msg)
{
	return gui ? gui->okcancel(msg) :
		print_cmdline(COL_BLUE "Question", msg);
}

void xcaWarningCore::sqlerror(QSqlError err)
{
	if (!err.isValid())
		err = QSqlDatabase::database().lastError();
	if (!err.isValid())
		return;
	if (gui)
		qCritical() << "SQL ERROR:" << err.text();

	warning(err.text());
}

void xcaWarningCore::error(const errorEx &err)
{
	if (err.isEmpty())
		 return;
	QString msg = QObject::tr("The following error occurred:") +
			"\n" + err.getString();
	if (gui)
		gui->error(msg);
}

void xcaWarningCore::setGui(class xcaWarning_i *g)
{
	delete gui;
	gui = g;
}
