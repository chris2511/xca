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
 *
 */                           


#include "ExportKey.h"
#include <iostream.h>


ExportKey::ExportKey(QString fname, bool onlypub, 
	QWidget *parent = 0,const char *name = 0)
	:ExportKey_UI(parent,name,true,0)
{
	filename->setText(fname);
	onlyPub = onlypub;
	if (onlyPub) {
		exportPrivate->setDisabled(true);
		encryptKey->setDisabled(true);
	}		
}
	
void ExportKey::chooseFile()
{
	QStringList filt;
	filt.append( "PKI Schlüssel ( *.pem *.der *.pk8 )"); 
	filt.append("Alle Dateien ( *.* )");
	QString s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	//dlg->setSelection( filename->text() );
	dlg->setCaption("Schlüssel speichern unter");
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::AnyFile );
	if (dlg->exec())
		s = dlg->selectedFile();
	if (! s.isEmpty()) filename->setText(s);
}

void ExportKey::canEncrypt() {
	if (exportFormat->currentText() == "PKCS#8") {
		//exportPrivate->setOn(true);
		exportPrivate->setDisabled(true);
		//encryptKey->setOn(true);
		encryptKey->setDisabled(true);
	}
	else if (exportFormat->currentText() == "PEM" && !onlyPub) {
		exportPrivate->setEnabled(true);
	    	if (exportPrivate->isOn())
			encryptKey->setEnabled(true);
	}
	else {
		encryptKey->setDisabled(true);
		//encryptKey->setOn(false);
	}

	if (onlyPub) {
		//exportPrivate->setOn(false);
		exportPrivate->setDisabled(true);
		//encryptKey->setOn(false);
		encryptKey->setDisabled(true);
	}
}
	
