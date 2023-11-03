/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCAWARNINGCORE_H
#define __XCAWARNINGCORE_H

#include "base.h"
#include "exception.h"
#include "x509v3ext.h"
#include <QSqlError>
#include <QSqlDatabase>

#define XCA_INFO(msg) xcaWarning::information(msg)
#define XCA_WARN(msg) xcaWarning::warning(msg)
#define XCA_YESNO(msg) xcaWarning::yesno(msg)
#define XCA_OKCANCEL(msg) xcaWarning::okcancel(msg)
#define XCA_ERROR(err) xcaWarning::error(err)
#define XCA_SQLERROR(err) xcaWarning::sqlerror(err)
#define XCA_PASSWD_ERROR() XCA_WARN(QObject::tr("Password verify error, please try again"))

class xcaWarning_i
{
  public:
	virtual void information(const QString &msg) = 0;
	virtual void warning(const QString &msg) = 0;
	virtual void warningv3(const QString &msg, const extList &el) = 0;
	virtual bool yesno(const QString &msg) = 0;
	virtual bool okcancel(const QString &msg) = 0;
	virtual void sqlerror(QSqlError err) = 0;
	virtual void error(const QString &msg) = 0;
	virtual ~xcaWarning_i() { };
};

class xcaWarningCore : public QObject, public xcaWarning_i
{
	Q_OBJECT

  protected:
	virtual bool print_cmdline(const char *color, const QString &msg);

  public:
	void information(const QString &msg);
	void warning(const QString &msg);
	bool yesno(const QString &msg);
	bool okcancel(const QString &msg);
	void sqlerror(QSqlError err);
	void warningv3(const QString &msg, const extList &el);
	void error(const QString &msg);
};

class xcaWarning
{
	static class xcaWarning_i *gui;

  public:
	xcaWarning() = delete;
	xcaWarning(const xcaWarningCore &) = delete;
	~xcaWarning() = delete;

	static void information(const QString &msg)
	{
		gui->information(msg);
	}
	static void warning(const QString &msg)
	{
		gui->warning(msg);
	}
	static void warningv3(const QString &msg, const extList &el)
	{
		gui->warningv3(msg, el);
	}
	static bool yesno(const QString &msg)
	{
		return gui->yesno(msg);
	}
	static bool okcancel(const QString &msg)
	{
		return gui->okcancel(msg);
	}
	static void sqlerror(QSqlError err)
	{
		if (!err.isValid())
			err = QSqlDatabase::database().lastError();
		if (err.isValid())
			gui->sqlerror(err);
	}
	static void error(const errorEx &err)
	{
		if (err.isEmpty())
			return;
		QString msg = QObject::tr("The following error occurred:") +
			"\n" + err.getString();
		gui->error(msg);
	}
	static void setGui(class xcaWarning_i *g)
	{
		delete gui;
		gui = g;
	}
};
#endif
