/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __EXPORTDIALOG_H
#define __EXPORTDIALOG_H

#include "ui_ExportDialog.h"

class ExportDialog: public QDialog, public Ui::ExportDialog
{
	Q_OBJECT

   protected:
	QStringList suffixes;
	QString filter;

   public:
	ExportDialog(QWidget *parent, QString fname);
	static bool mayWriteFile(const QString &fname);

   public slots:
	void on_fileBut_clicked();
	void on_exportFormat_activated(int);
	void accept();
};

class ExportDer: public ExportDialog
{
        Q_OBJECT
   public:
	ExportDer(QWidget *parent, QString fname, QString _filter)
		:ExportDialog(parent, fname)
	{
		QStringList sl; sl << "PEM" << "DER";
		exportFormat->addItems(sl);
		suffixes << "pem" << "der";
		filter = _filter + ";;" + tr("All files ( * )");
		formatLabel->setText(tr(
			"DER is a binary format\n"
			"PEM is a base64 encoded DER file\n"));
	}
};

class ExportCert: public ExportDialog
{

        Q_OBJECT
   public:
	ExportCert(QWidget *parent, QString fname, bool hasKey)
		:ExportDialog(parent, fname)
	{
		QStringList sl;
		sl <<   "PEM" <<
			"PEM with Certificate chain" <<
			"PEM all trusted Certificates" <<
			"PEM all Certificates" <<
			"DER" <<
			"PKCS #7" <<
			"PKCS #7 with Certificate chain" <<
			"PKCS #7 all trusted Certificates" <<
			"PKCS #7 all Certificates";

		if (hasKey) {
			sl <<   "PKCS #12" <<
				"PKCS #12 with Certificate chain" <<
				"PEM Cert + key" <<
				"PEM Cert + PKCS8 key";
		}
		exportFormat->addItems(sl);
		suffixes << "crt" << "crt" << "crt" << "crt" << "cer" <<
			"p7b" << "p7b" << "p7b" << "p7b" <<
			"p12" << "p12" << "pem" << "pem";

		filter = tr("X509 Certificates ( *.cer *.crt *.p12 *.p7b);;All files ( * )");
		formatLabel->setText(tr(
			"DER is a binary format of the Certificate\n"
			"PEM is a base64 encoded Certificate\n"
			"PKCS#7 is an official Certificate exchange format\n"
			"PKCS#12 is an encrypted official Key-Certificate exchange format\n"));
		filenameLabel->setText(tr(
			"Please enter the filename for the certificate."));
		label->setText(tr("Certifikate export"));
	}
};

#endif
