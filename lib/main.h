/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __MAIN_H
#define __MAIN_H

#include <QtGui/QApplication>
#include <QtCore/QTranslator>
#include "widgets/MainWindow.h"
#ifdef WIN32
#include <windows.h>
#endif

class XCA_application : public QApplication
{
	Q_OBJECT

private:
	MainWindow *mainw;
	QTranslator qtTr;
	QTranslator xcaTr;

public:
	XCA_application(int &argc, char *argv[]);
	void setMainwin(MainWindow *m);

protected:
	bool event(QEvent *ev);

signals:
	void openFiles(QStringList &);
};
#endif
