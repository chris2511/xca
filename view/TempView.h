
//Added by the Qt porting tool:
#include <QPixmap>

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


#ifndef TEMPVIEW_H
#define TEMPVIEW_H

#include "XcaListView.h"
#include "lib/pki_temp.h"
#ifdef qt4
#include <Qt/q3listview.h>
#else
#include <Qt/q3listview.h>
#endif


class TempView : public XcaListView
{
  Q_OBJECT

  private:
	QPixmap *keyicon;
	bool runTempDlg(pki_temp *);
  public:
	TempView(QWidget * parent = 0, const char * name = 0, Qt::WFlags f = 0);
	void showItem(pki_base *item, bool import);
	void newItem(int type);
	void updateViewItem(pki_base *);
	bool alterTemp(pki_temp *);
	void popupMenu(Q3ListViewItem *item, const QPoint &pt, int x);
	pki_base *loadItem(QString fname);
  public slots:
	void newEmptyTemp();
	void newCaTemp();
	void newClientTemp();
	void newServerTemp();
	void certFromTemp();
	void reqFromTemp();
	void alterTemp();
	void deleteItem();
	void store();
	void load();
  signals:
	void newReq(pki_temp *);
	void newCert(pki_temp *);
};	

#endif
