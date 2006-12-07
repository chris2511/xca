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

#ifndef _XCATREEVIEW_H
#define _XCATREEVIEW_H

#include <Qt/qtreeview.h>
#include <Qt/qitemselectionmodel.h>
#include <Qt/qsortfilterproxymodel.h>
#include "lib/db_base.h"

class db_base;
class XcaTreeView: public QTreeView
{
	Q_OBJECT
   protected:
	db_base *basemodel;
	QSortFilterProxyModel *proxy;
   public:
	XcaTreeView(QWidget *parent = 0);
	~XcaTreeView();
	void contextMenuEvent(QContextMenuEvent * e);
	void setModel(QAbstractItemModel *model);
	QModelIndex getIndex(const QModelIndex &index);
	QModelIndex getProxyIndex(const QModelIndex &index);
	QModelIndexList getSelectedIndexes();
	void columnsResize();

};

class CertTreeView: public XcaTreeView
{
   public:
	CertTreeView(QWidget *parent = 0);
};

class XcaProxyModel: public QSortFilterProxyModel
{
	Q_OBJECT
   public:
	XcaProxyModel(QWidget *parent = 0);
	bool lessThan(const QModelIndex &left, const QModelIndex &right) const;
};


#endif
