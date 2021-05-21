/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCAWARNINGCORE_H
#define __XCAWARNINGCORE_H

#include "lib/base.h"
#include "lib/exception.h"
#include <QSqlError>

#define XCA_INFO(msg) xcaWarningCore::information(msg)
#define XCA_WARN(msg) xcaWarningCore::warning(msg)
#define XCA_YESNO(msg) xcaWarningCore::yesno(msg)
#define XCA_OKCANCEL(msg) xcaWarningCore::okcancel(msg)
#define XCA_ERROR(err) xcaWarningCore::error(err)
#define XCA_SQLERROR(err) xcaWarningCore::sqlerror(err)
#define XCA_PASSWD_ERROR() XCA_WARN(QObject::tr("Password verify error, please try again"))

class xcaWarning_i
{
    public:
	virtual void information(const QString &msg) = 0;
	virtual void warning(const QString &msg) = 0;
	virtual bool yesno(const QString &msg) = 0;
	virtual bool okcancel(const QString &msg) = 0;
	virtual void error(const errorEx &err) = 0;
	virtual ~xcaWarning_i() { };
};

class xcaWarningCore
{
	static class xcaWarning_i *gui;

    public:
	xcaWarningCore() = delete;
	xcaWarningCore(const xcaWarningCore &) = delete;
	~xcaWarningCore() = delete;

	static void information(const QString &msg);
	static void warning(const QString &msg);
	static bool yesno(const QString &msg);
	static bool okcancel(const QString &msg);
	static void sqlerror(QSqlError err);
	static void error(const errorEx &err);
	static void setGui(class xcaWarning_i *g);
};
#endif
