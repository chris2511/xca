/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2018 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCAWARNING_H
#define __XCAWARNING_H

#include <QMessageBox>

#define XCA_INFO(msg) xcaWarning::information(msg)
#define XCA_WARN(msg) xcaWarning::warning(msg)
#define XCA_YESNO(msg) xcaWarning::yesno(msg)
#define XCA_OKCANCEL(msg) xcaWarning::okcancel(msg)

class xcaWarning: public QMessageBox
{
    public:
	xcaWarning(QWidget *w, QString txt,
				QMessageBox::Icon icon = QMessageBox::Warning)
		: QMessageBox(icon, XCA_TITLE, txt, QMessageBox::NoButton, w)
	{
		setTextFormat(Qt::PlainText);
	}
	static void information(QString msg)
	{
		xcaWarning m(NULL, msg, QMessageBox::Information);
		m.setStandardButtons(QMessageBox::Ok);
		m.exec();
	}
	static void warning(QString msg)
	{
		xcaWarning m(NULL, msg, QMessageBox::Warning);
		m.setStandardButtons(QMessageBox::Ok);
		m.exec();
	}
	static bool yesno(QString msg)
	{
		xcaWarning m(NULL, msg, QMessageBox::Question);
		m.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
		return m.exec() == QMessageBox::Yes;
	}
	static bool okcancel(QString msg)
	{
		xcaWarning m(NULL, msg, QMessageBox::Warning);
		m.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
		return m.exec() == QMessageBox::Ok;
	}
};
#endif
