/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __EXPORTDIALOG_H
#define __EXPORTDIALOG_H

#include "ui_ExportDialog.h"
#include "lib/pki_export.h"
#include <QModelIndexList>

class QPixmap;
class pki_base;

class ExportDialog: public QDialog, public Ui::ExportDialog
{
	Q_OBJECT

  protected:
	QString filter{}, savedFile{}, filenameLabelOrig{};
	QList<const pki_export*> alltypes;

  public:
	ExportDialog(QWidget *w, const QString &title, const QString &filt,
		     const QModelIndexList &indexes, const QPixmap &img,
		     QList<const pki_export*> types,
		     const QString &help_ctx = QString());
	~ExportDialog();
	const pki_export *export_type(int idx = -1) const;
	static bool mayWriteFile(const QString &fname, bool inSeparateFiles);
	void setupExportFormat(int disable_flag);

  public slots:
	void on_fileBut_clicked();
	void on_separateFiles_clicked(bool checked);
	void on_exportFormat_activated(int);
	void on_exportFormat_highlighted(int index);
	void accept();
};

#endif
