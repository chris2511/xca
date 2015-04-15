/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __EXPORTDIALOG_H
#define __EXPORTDIALOG_H

#include "ui_ExportDialog.h"
#include "lib/pki_base.h"

class MainWindow;
class QPixmap;

class exportType {
    public:
	enum etype { Separator, PEM, PEM_chain, PEM_trusted, PEM_all,
		DER, PKCS7, PKCS7_chain, PKCS7_trusted, PKCS7_all,
		PKCS12, PKCS12_chain, PEM_cert_key, PEM_cert_pk8,
		PEM_key, PEM_private, PEM_private_encrypt, DER_private,
		DER_key, PKCS8, PKCS8_encrypt, SSH2_public,
		PEM_selected, PKCS7_selected,
		ETYPE_max };
	enum etype type;
	QString desc;
	QString extension;
	exportType(enum etype t, QString e, QString d) {
		type = t; extension = e; desc = d;
	}
	exportType() { type = Separator; }
};
Q_DECLARE_METATYPE(exportType);

class ExportDialog: public QDialog, public Ui::ExportDialog
{
	Q_OBJECT

   protected:
	QString filter;
	MainWindow *mainwin;
	QVector<QString> help;

   public:
	ExportDialog(MainWindow *mw, QString title, QString filt,
			pki_base *pki, QPixmap *img, QList<exportType> types);
	static bool mayWriteFile(const QString &fname);
	enum exportType::etype type();

   public slots:
	void on_fileBut_clicked();
	void on_exportFormat_activated(int);
	void on_exportFormat_highlighted(int index);
	void accept();
};

#endif
