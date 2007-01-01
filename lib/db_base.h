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
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */

#ifndef DB_BASE_H
#define DB_BASE_H

#include "db.h"
#include "base.h"
#include "load_obj.h"
#include <Qt/qlistview.h>
#include <Qt/qpixmap.h>
#include <Qt/qstringlist.h>
#include <Qt/qpixmap.h>
#include <Qt/qabstractitemmodel.h>
#include "pki_base.h"
#include "widgets/XcaTreeView.h"

#define FOR_ALL_pki(pki, pki_type) \
	for(pki_type *pki=(pki_type*)rootItem->iterate(); pki; pki=(pki_type*)pki->iterate())

class MainWindow;
class QContextMenuEvent;
class XcaTreeView;
class NewX509;

class db_base: public QAbstractItemModel
{
	Q_OBJECT

    protected:
	QString dbName, delete_txt;
	QModelIndex currentIdx;
	void _writePKI(pki_base *pki, bool overwrite );
	void _removePKI(pki_base *pki );
	void removeItem(QString k);
	enum pki_type pkitype;
	QList<QVariant> headertext;
	MainWindow *mainwin;
	XcaTreeView *view;
	QString class_name;

    public:
	pki_base *rootItem;
	db_base(QString db, MainWindow *mw);
	virtual ~db_base();
	virtual pki_base *newPKI();
	virtual void insertPKI(pki_base *pki);
	virtual void updatePKI(pki_base *pki);
	pki_base *getByName(QString desc);
	pki_base *getByReference(pki_base *refpki);
	pki_base *getByPtr(void *);
	virtual void loadContainer();
	QStringList getDesc();
	virtual pki_base* insert(pki_base *item);
	virtual void inToCont(pki_base *pki);
	virtual void remFromCont(QModelIndex &idx);

	QPixmap *loadImg(const char *name);
	void writeAll(void);
	void dump(QString dirname);
	virtual void showContextMenu(QContextMenuEvent * e,
			const QModelIndex &index){};

	QModelIndex index(int row, int column, const QModelIndex &parent)const;
	QModelIndex index(pki_base *pki)const;
	QModelIndex parent(const QModelIndex &index) const;
	int rowCount(const QModelIndex &parent) const;
	int columnCount(const QModelIndex &parent) const;
	QVariant data(const QModelIndex &index, int role) const;
	QVariant headerData(int section, Qt::Orientation orientation,
			int role) const;
	Qt::ItemFlags flags(const QModelIndex &index) const;
	bool setData(const QModelIndex &index, const QVariant &value, int role);
	void deleteSelectedItems(XcaTreeView* view);
	void showSelectedItems(XcaTreeView *view);
	void storeSelectedItems(XcaTreeView *view);
	void load_default(load_base &load);
	void insertChild(pki_base *parent, pki_base *child);
	virtual void showItem(const QModelIndex &index) {};

    public slots:
	void deletePKI();
	void delete_ask();
	void edit();
	virtual void showItem();
	virtual void store(){};

    signals:
	void connNewX509(NewX509 *dlg);
};

#endif
