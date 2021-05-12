/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __EXPORTDIALOG_H
#define __EXPORTDIALOG_H

#include "ui_ExportDialog.h"
#include "lib/exportType.h"

class QPixmap;
class pki_base;

class ExportDialog: public QDialog, public Ui::ExportDialog
{
	Q_OBJECT

   protected:
	QString filter;
	QVector<QString> help;

   public:
	ExportDialog(QWidget *w, const QString &title, const QString &filt,
		     pki_base *pki, const QPixmap &img, QList<exportType> types,
		     const QString &help_ctx = QString());
	static bool mayWriteFile(const QString &fname);
	enum exportType::etype type();

   public slots:
	void on_fileBut_clicked();
	void on_exportFormat_activated(int);
	void on_exportFormat_highlighted(int index);
	void accept();
};

#endif
