/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __EXPORTKEY_H
#define __EXPORTKEY_H

#include "ui_ExportKey.h"

class ExportKey: public QDialog, public Ui::ExportKey
{
	Q_OBJECT
   private:
	bool onlyPub;
   public:
	ExportKey(QWidget *parent, QString fname, bool onlypub);
   public slots:
	void on_fileBut_clicked();
	void canEncrypt();
	void on_exportFormat_activated(int);
	void on_exportPrivate_stateChanged();
	void on_exportPkcs8_stateChanged();
	void on_okButton_clicked();
};
#endif
