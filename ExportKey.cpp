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
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
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


ExportKey::ExportKey(QString fname, bool onlypub, QString dpath,
	QWidget *parent, const char *name )
	:ExportKey_UI(parent,name,true,0)
{
	filename->setText(fname);
	setCaption(tr(XCA_TITLE));
	onlyPub = onlypub;
	exportFormat->insertItem("PEM");
	exportFormat->insertItem("DER");
	if (onlyPub) {
		privFrame->setDisabled(true);
		exportPrivate->setDisabled(true);
		encryptKey->setDisabled(true);
	}		
	else {
		exportPrivate->setChecked(true);
		exportFormat->insertItem("PKCS#8");
	}
	canEncrypt();	
	dirPath = dpath;
}
	
void ExportKey::chooseFile()
{
	QStringList filt;
	filt.append(tr("RSA Keys ( *.pem *.der *.pk8 )")); 
	filt.append(tr("All Files ( *.* )"));
	QString s = "";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Save RSA key as"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::AnyFile );
	dlg->setSelection( filename->text() );
	dlg->setDir(dirPath);
	if (dlg->exec())
		s = dlg->selectedFile();
	if (! s.isEmpty()) {
		QDir::convertSeparators(s);
		filename->setText(s);
	}
	dirPath = dlg->dirPath();
	delete dlg;
}

void ExportKey::canEncrypt() {
	CERR("TOGGEL");
	if (exportFormat->currentText() == "PKCS#8") {
		exportPrivate->setChecked(true);
		exportPrivate->setDisabled(true);
		encryptKey->setChecked(true);
		encryptKey->setDisabled(true);
	}
	else if (exportFormat->currentText() == "PEM" && !onlyPub) {
		exportPrivate->setEnabled(true);
	    	if (exportPrivate->isChecked()) {
			encryptKey->setEnabled(true);
		}
		else {
			encryptKey->setEnabled(false);
		}
	}
	else {
		encryptKey->setDisabled(true);
		encryptKey->setChecked(false);
		exportPrivate->setEnabled(true);
	}

	if (onlyPub) {
		exportPrivate->setChecked(false);
		exportPrivate->setDisabled(true);
		encryptKey->setChecked(false);
		encryptKey->setDisabled(true);
	}
}
	
