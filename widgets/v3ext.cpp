/* vi: set sw=4 ts=4: */
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


#include "v3ext.h"
#include <qlabel.h>
#include <qlistbox.h>
#include <qcombobox.h>
#include <qlistview.h>
#include <qlineedit.h>
#include <qstringlist.h>
#include <qmessagebox.h>
#include "MainWindow.h"
#include "lib/exception.h"

v3ext::v3ext(QWidget *parent, const char *name, bool modal, WFlags f )
	:v3ext_UI(parent, name, modal, f)
{
	setCaption(tr(XCA_TITLE));
	listView->addColumn(tr("Type"));
	listView->addColumn(tr("Content"));
}

v3ext::~v3ext()
{
}

void v3ext::addInfo(QLineEdit *myle, const QStringList &sl, int n,
		X509 *s, X509 *s1)
{
	type->insertStringList(sl);
	nid = n;
	le = myle;
	if (le)
		addItem(le->text());
	
	memset(&ext_ctx, 0, sizeof(X509V3_CTX));
	X509V3_set_ctx(&ext_ctx, s, s1, NULL, NULL, 0);
}

void v3ext::addItem(QString list)
{
	unsigned int i;
	QStringList sl;
	sl = sl.split(',', list);
	for (i=0; i< sl.count(); i++)
		addEntry(sl[i]);	
}

/* for one TYPE:Content String */
void v3ext::addEntry(QString line)
{
	int i;
	i = line.find(':');
	new QListViewItem(listView, line.left(i), line.right(line.length()-(i+1)));
}

QString v3ext::toString()
{
	QStringList str;
	QListViewItem *lvi = listView->firstChild();
	while (lvi != NULL) {
		QString s;
		s = lvi->text(0).stripWhiteSpace();
		if (!s.contains(':'))
			s += ":" + lvi->text(1).stripWhiteSpace();
		str += s;	
		lvi = lvi->nextSibling();
	}
	return str.join(",");
}


void v3ext::delEntry()
{
	listView->removeItem(listView->currentItem());
}
	
void v3ext::addEntry()
{
	QString typ, cont;
	typ = type->currentText();
	if ( ! typ.contains(':') )
		cont = value->text();
	
	new QListViewItem(listView, typ, cont);
}

void v3ext::apply()
{
	le->setText(toString());
	__validate(false);
	accept();
}

bool v3ext::__validate(bool showSuccess)
{
	x509v3ext ext;
	QString str, error;
	
	if (nid==NID_info_access) {
		str = "OCSP;";
	}
	str += toString();
	
	ext.create(nid, str, &ext_ctx);
	while (int i = ERR_get_error() ) {
		error += ERR_error_string(i ,NULL);
		error += "\n";
	}
	if (! error.isEmpty()) {
		QMessageBox::warning(NULL, XCA_TITLE, tr("Validation failed:\n")
			+ "'" + str + "'\n" + error, tr("&OK"));
		 return false;
	}
	if (showSuccess) {
		QMessageBox::information(NULL, XCA_TITLE,
			"Validation successfull:\n'" + ext.getValue() + "'", tr("&OK"));
	}
	return true;
}

void v3ext::validate()
{
	__validate(true);
}
