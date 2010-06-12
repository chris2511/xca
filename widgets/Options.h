/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __OPTIONS_H
#define __OPTIONS_H

#include "ui_Options.h"
#include <QtGui/QDialog>
#include "lib/base.h"
#include "widgets/MainWindow.h"

class Options: public QDialog, public Ui::Options
{
		Q_OBJECT
	private:
		QStringList string_opts;
		MainWindow *mw;
	public:
		Options(MainWindow *parent);
	public slots:
		void on_extDNadd_clicked();
		void on_extDNdel_clicked();
		QString getDnString();
		void setStringOpt(const QString string_opt);
		QString getStringOpt();
		void on_fileButton_clicked(void);
		void on_tryLoadButton_clicked(void);
};

#endif
