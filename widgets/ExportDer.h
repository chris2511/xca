/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __EXPORTDER_H
#define __EXPORTDER_H

#include "ui_ExportDer.h"

class ExportDer: public QDialog, public Ui::ExportDer
{
	Q_OBJECT

   private:
	QString filter;

   public:
	ExportDer(QWidget *parent, QString fname, QString _filter);

   public slots:
	void on_fileBut_clicked();
	void on_exportFormat_activated(int);
};

#endif
