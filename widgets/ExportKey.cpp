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


#include "ExportKey.h"
#include "lib/base.h"

#include <Qt/qfiledialog.h>
#include <Qt/qcheckbox.h>
#include <Qt/qlineedit.h>
#include <Qt/qcombobox.h>
#include <Qt/qfiledialog.h>

ExportKey::ExportKey(QWidget *parent, QString fname, bool onlypub)
	:QDialog(parent)
{
	setupUi(this);
	filename->setText(fname);
	setWindowTitle(tr(XCA_TITLE));
	onlyPub = onlypub;
	exportFormat->addItem("PEM");
	exportFormat->addItem("DER");
	if (onlyPub) {
		exportPrivate->setDisabled(true);
		exportPkcs8->setDisabled(true);
		encryptKey->setDisabled(true);
	}
	else {
		exportPrivate->setChecked(true);
	}
	canEncrypt();
}

void ExportKey::on_fileBut_clicked()
{
	QString s = QFileDialog::getSaveFileName(this, tr("Save key as"),
		filename->text(),
		tr("Private keys ( *.pem *.der *.pk8 );;All files ( *.* )"));
	if (! s.isEmpty()) {
		QDir::convertSeparators(s);
		filename->setText(s);
	}
}

void ExportKey::on_exportPkcs8_stateChanged()
{
	canEncrypt();
}

void ExportKey::canEncrypt()
{
	if ((exportFormat->currentText() == "DER" &&
			!exportPkcs8->isChecked()) ||
			onlyPub || !exportPrivate->isChecked())
	{
		encryptKey->setDisabled(true);
	} else {
		encryptKey->setEnabled(true);
	}
}

void ExportKey::on_exportFormat_activated(int c)
{
	char *suffix[] = { "pem", "der" };

	QString fn = filename->text();
	QString nfn = fn.left(fn.lastIndexOf('.')+1) + suffix[c];
	filename->setText(nfn);
	canEncrypt();
}

void ExportKey::on_exportPrivate_stateChanged()
{
	if (exportPrivate->isChecked()) {
		exportPkcs8->setEnabled(true);
	} else {
		exportPkcs8->setEnabled(false);
		exportPkcs8->setChecked(false);
	}
	canEncrypt();
}
