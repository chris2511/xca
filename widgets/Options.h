/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 20012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __OPTIONS_H
#define __OPTIONS_H

#include "ui_Options.h"
#include <QDialog>
#include "lib/base.h"
#include "SearchPkcs11.h"
#include "MainWindow.h"

class Options: public QDialog, public Ui::Options
{
		Q_OBJECT
	private:
		SearchPkcs11 *searchP11;
		QStringList string_opts;
		QString getDnString(QListWidget *w);
		void setDnString(QString dn, QListWidget *w);

	public:
		Options(QWidget *parent);
		~Options();
		int exec();

	public slots:
		void on_extDNadd_clicked();
		void on_extDNdel_clicked();
		void on_expDNadd_clicked();
		void on_expDNdel_clicked();
		void on_expDNdefault_clicked();
		void on_addButton_clicked(void);
		void on_removeButton_clicked(void);
		void on_searchPkcs11_clicked(void);
		void addLib(QString);
};

#endif
