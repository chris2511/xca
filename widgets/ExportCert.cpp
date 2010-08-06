/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ExportCert.h"
#include "lib/base.h"
#include "lib/func.h"

#include <QtGui/QComboBox>
#include <QtGui/QLineEdit>
#include <QtGui/QFileDialog>
#include <QtGui/QMessageBox>
#include <QtCore/QStringList>

ExportCert::ExportCert(QWidget *parent, QString fname, bool hasKey)
	:QDialog(parent)
{
	setupUi(this);
	filename->setText(fname);
	setWindowTitle(tr(XCA_TITLE));
	QStringList sl;
	sl << "PEM" << "PEM with Certificate chain" <<
		"PEM all trusted Certificates" << "PEM all Certificates" <<
		"DER" << "PKCS #7" << "PKCS #7 with Certificate chain" <<
		"PKCS #7 all trusted Certificates" <<"PKCS #7 all Certificates";

	if (hasKey) {
		sl << "PKCS #12" << "PKCS #12 with Certificate chain" <<
			"PEM Cert + key" << "PEM Cert + PKCS8 key";
	}
	exportFormat->addItems(sl);
}

void ExportCert::on_fileBut_clicked()
{
	QString s = QFileDialog::getSaveFileName(this, tr("Save key as"),
		filename->text(),
		tr("X509 Certificates ( *.cer *.crt *.p12 );;All files ( * )"),
		NULL, QFileDialog::DontConfirmOverwrite);

	if (!s.isEmpty()) {
		QDir::convertSeparators(s);
		filename->setText(s);
	}
	on_exportFormat_activated(0);
}

void ExportCert::on_exportFormat_activated(int c)
{
	QStringList suffix;
	suffix << "crt" << "crt" << "crt" << "crt" << "cer" << "p7b" <<
		"p7b" << "p7b" << "p7b" << "p12" << "p12" << "pem" << "pem";

	filename->setText(changeFilenameSuffix(filename->text(), suffix, c));
}

void ExportCert::accept()
{
	if (mayWriteFile(filename->text()))
		QDialog::accept();
}
