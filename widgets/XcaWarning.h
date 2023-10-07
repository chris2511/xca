/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCAWARNING_H
#define __XCAWARNING_H

#include "lib/XcaWarningCore.h"
#include <QMessageBox>

class xcaWarningBox: public QMessageBox
{
	Q_OBJECT

	public:
		xcaWarningBox(QWidget *w, const QString &txt,
			QMessageBox::Icon icn = QMessageBox::Warning);
		void addButton(QMessageBox::StandardButton button,
			const QString &text = QString());
};

class xcaWarningGui : public QObject, public xcaWarning_i
{
	Q_OBJECT

	int showBox(const QString &txt, QMessageBox::Icon icn,
			QMessageBox::StandardButtons b);
  public:
	void information(const QString &msg);
	void warning(const QString &msg);
	void warningv3(const QString &msg, const extList &el);
	bool yesno(const QString &msg);
	bool okcancel(const QString &msg);
	void sqlerror(QSqlError err);
	void error(const QString &msg);
};
#endif
