/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 *	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.trolltech.com
 *
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
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
		tr("X509 Certificates ( *.cer *.crt *.p12 );;All files ( *.* )"));
	if (! s.isEmpty()) {
		QDir::convertSeparators(s);
		filename->setText(s);
	}
	on_exportFormat_activated(0);
}

void ExportCert::on_exportFormat_activated(int)
{
	char *suffix[] = { "crt", "crt", "crt", "crt", "cer",
		"p7b", "p7b", "p7b", "p7b", "p12", "p12", "pem", "pem" };
	int selected = exportFormat->currentIndex();
	QString fn = filename->text();
	QString nfn = fn.left(fn.lastIndexOf('.')+1) + suffix[selected];
	filename->setText(nfn);
}

