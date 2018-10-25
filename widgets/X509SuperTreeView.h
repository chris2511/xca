/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __X509SUPERTREEVIEW_H
#define __X509SUPERTREEVIEW_H

#include "XcaTreeView.h"
#include "lib/db_x509req.h"

class X509SuperTreeView: public XcaTreeView
{
	Q_OBJECT
	db_x509super *x509super;

    public:
	QMenu *transform;
	X509SuperTreeView(QWidget *parent) : XcaTreeView(parent)
	{
		x509super = NULL;
	}
	void fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes);
	void setModel(QAbstractItemModel *model=NULL)
	{
		x509super = dynamic_cast <db_x509super*> (model);
		XcaTreeView::setModel(model);
	}

    public slots:
	void extractPubkey();
	void toTemplate();
	void toOpenssl();
};
#endif
