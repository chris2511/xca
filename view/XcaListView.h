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


#ifndef XCALISTVIEW_H
#define XCALISTVIEW_H

#include <qlistview.h>
#include "lib/db_base.h"
#include "lib/load_obj.h"
#include "lib/exception.h"
#include "widgets/NewX509.h"

#define CHECK_DB emit init_database();
	
class XcaListView : public QListView
{
	Q_OBJECT
		
	protected:
		db_base *db;
   
	public:
		XcaListView(QWidget * parent = 0, const char * name = 0, WFlags f = 0);
		void setDB(db_base *mydb);
		void rmDB(db_base *mydb);
		virtual pki_base *getSelected();
		virtual void showItem(pki_base *item, bool import);
		void deleteItem_default(QString t1, QString t2);
		void load_default(QStringList &filter, QString caption);
		void load_default(load_base &load);
		void setDB(db_base *mydb, QPixmap *myimage);
		void Error(errorEx &err);
		bool Error(pki_base *pki);
		void loadCont();
	public slots:
		virtual void newItem();
		virtual void deleteItem();
		void showItem();
		void showItem(QString name);
		void showItem(QListViewItem *item);
		virtual void load();
		virtual	void store();
		virtual void popupMenu(QListViewItem *item, const QPoint &pt, int x);
		void startRename();
		void renameDialog();
		void rename(QListViewItem *item, int col, const QString &text);
		virtual void updateView();
	signals:
		void init_database();
		void connNewX509(NewX509 *);
		void showKey(QString name);
};

#endif
