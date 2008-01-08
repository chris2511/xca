/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ExportCert.h"
#include "lib/base.h"

#include <qcombobox.h>
#include <qlineedit.h>
#include <qfiledialog.h>

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
		tr("X509 Certificates ( *.cer *.crt *.p12 );;All files ( * )"));
	if (! s.isEmpty()) {
		QDir::convertSeparators(s);
		filename->setText(s);
	}
	on_exportFormat_activated(0);
}

void ExportCert::on_exportFormat_activated(int)
{
	const char *suffix[] = { "crt", "crt", "crt", "crt", "cer",
		"p7b", "p7b", "p7b", "p7b", "p12", "p12", "pem", "pem" };
	int selected = exportFormat->currentIndex();
	QString fn = filename->text();
	QString nfn = fn.left(fn.lastIndexOf('.')+1) + suffix[selected];
	filename->setText(nfn);
}

