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


#include "ExportCert.h"


ExportCert::ExportCert(QString fname, bool hasKey, QString dpath,
	const QString tcafn, QWidget *parent, const char *name )
	:ExportCert_UI(parent,name,true,0)
{
	filename->setText(fname);
	setCaption(tr(XCA_TITLE));
	exportFormat->insertItem("PEM");
	exportFormat->insertItem("PEM with Certificate chain");
	exportFormat->insertItem("PEM all trusted Certificates");
	exportFormat->insertItem("PEM all Certificates");
	exportFormat->insertItem("DER");
	exportFormat->insertItem("PKCS #7");
	exportFormat->insertItem("PKCS #7 with Certificate chain");
	exportFormat->insertItem("PKCS #7 all trusted Certificates");
	if (hasKey) {
		exportFormat->insertItem("PKCS #12");
		exportFormat->insertItem("PKCS #12 with Certificate chain");
	}		
	dirPath = dpath;
	tinyCAfname = tcafn;
}
	
void ExportCert::chooseFile()
{
	QStringList filt;
	filt.append(tr("X509 Certificates ( *.cer *.crt *.p12 )")); 
	filt.append(tr("All Files ( *.* )"));
	QString s = "";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Save Certificate as"));
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
	dirPath= dlg->dirPath();
	formatChanged();
	delete dlg;
}

void ExportCert::formatChanged()
{
	CERR("Export format changed");
	char *suffix[] = {"crt", "crt", "crt", "crt", "cer", "p7b", "p7b", "p7b", "p12", "p12"};
	int selected = exportFormat->currentItem();
	QString fn = filename->text();
	QString nfn = fn.left(fn.findRev('.')+1) + suffix[selected];
	CERR(nfn);
	filename->setText(nfn);
}	

void ExportCert::setTinyCAfname()
{
	filename->setText(tinyCAfname);
}

