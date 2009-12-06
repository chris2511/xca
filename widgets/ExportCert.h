/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __EXPORTCERT_H
#define __EXPORTCERT_H

#include "ui_ExportCert.h"

class ExportCert: public QDialog, public Ui::ExportCert
{
	Q_OBJECT

   private:
	QString tinyCAfname;

   public:
	ExportCert(QWidget *parent, QString fname, bool hasKey);

   public slots:
	void on_fileBut_clicked();
	void on_exportFormat_activated(int);
	void on_okButton_clicked();
};

#endif
