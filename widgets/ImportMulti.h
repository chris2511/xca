/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __IMPORTMULTI_H
#define __IMPORTMULTI_H

#include "ui_ImportMulti.h"
#include "lib/db_base.h"
#include <qlist.h>

class pki_x509;
class pki_key;

class ImportMulti: public QDialog, private Ui::ImportMulti
{
	Q_OBJECT

	private:
		db_base *mcont;
		MainWindow *mainwin;
	public:
		ImportMulti(MainWindow *parent);
		~ImportMulti();
		void addItem(pki_base *pki);
		pki_base *getSelected();
		void import(QModelIndex &idx);
		void execute(int force=0);
		int entries();

	public slots:
		void on_butRemove_clicked();
		void on_butImport_clicked();
		void on_butDetails_clicked();
		void on_butOk_clicked();

};

#endif
