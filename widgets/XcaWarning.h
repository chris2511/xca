/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCAWARNING_H
#define __XCAWARNING_H

#include "lib/base.h"
#include "lib/exception.h"
#include <QMessageBox>
#include <QMap>
#include <QSqlError>

#define XCA_INFO(msg) xcaWarning::information(msg)
#define XCA_WARN(msg) xcaWarning::warning(msg)
#define XCA_YESNO(msg) xcaWarning::yesno(msg)
#define XCA_OKCANCEL(msg) xcaWarning::okcancel(msg)
#define XCA_ERROR(err) xcaWarning::error(err)
#define XCA_SQLERROR(err) xcaWarning::sqlerror(err)
#define XCA_PASSWD_ERROR() XCA_WARN(QObject::tr("Password verify error, please try again"))

class xcaWarning: public QObject
{
	Q_OBJECT

    private:
	QMessageBox *m;
	QMessageBox::StandardButtons buttons;
	QMap<QMessageBox::StandardButton, QString> button_texts;
	QMessageBox::Icon icon;
	QString msg;

    public:
	xcaWarning(QWidget *w, const QString &txt,
			QMessageBox::Icon icn = QMessageBox::Warning);
	~xcaWarning();
	void setStandardButtons(QMessageBox::StandardButtons b);
	void addButton(QMessageBox::StandardButton button,
			const QString &text = QString());
	int exec();

	static void information(const QString &msg);
	static void warning(const QString &msg);
	static bool yesno(const QString &msg);
	static bool okcancel(const QString &msg);
	static void sqlerror(QSqlError err);
	static void error(const errorEx &err);
};
#endif
