/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef OPTIONS_H
#define OPTIONS_H

#include "ui_Options.h"
#include <qdialog.h>
#include "lib/base.h"
#include "widgets/MainWindow.h"

class Options: public QDialog, public Ui::Options
{
		Q_OBJECT
	public:
		Options(QWidget *parent, QString dn);
	public slots:
		void on_extDNadd_clicked();
		void on_extDNdel_clicked();
		QString getDnString();
};

#endif
