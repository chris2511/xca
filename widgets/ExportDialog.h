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

class QPixmap;

class exportType {
    public:
	enum etype { Separator, PEM, PEM_chain, PEM_unrevoked, PEM_all,
		DER, PKCS7, PKCS7_chain, PKCS7_unrevoked, PKCS7_all,
		PKCS12, PKCS12_chain, PEM_cert_key, PEM_cert_pk8,
		PEM_key, PEM_private, PEM_private_encrypt, DER_private,
		DER_key, PKCS8, PKCS8_encrypt, SSH2_public,
		PEM_selected, PKCS7_selected, Index, vcalendar, vcalendar_ca,
		PVK_private, PVK_encrypt, SSH2_private, ETYPE_max };
	enum etype type;
	QString desc;
	QString extension;
	exportType(enum etype t, QString e, QString d) {
		type = t; extension = e; desc = d;
	}
	exportType() { type = Separator; }
	bool isPEM() const {
		switch (type) {
		case PEM:
		case PEM_chain:
		case PEM_unrevoked:
		case PEM_all:
		case PEM_cert_key:
		case PEM_cert_pk8:
		case PEM_key:
		case PEM_private:
		case PEM_private_encrypt:
		case PEM_selected:
		case SSH2_private:
			return true;
		default:
			return false;
		}
	}
};
Q_DECLARE_METATYPE(exportType);

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
