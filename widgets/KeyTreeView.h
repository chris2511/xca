/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __KEYTREEVIEW_H
#define __KEYTREEVIEW_H

#include "XcaTreeView.h"
#include "lib/db_key.h"

class KeyTreeView: public XcaTreeView
{
	Q_OBJECT
	db_key *keys;

    public:
	KeyTreeView(QWidget *parent) : XcaTreeView(parent)
	{
		keys = NULL;
	}
	void fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes);
	void setModel(QAbstractItemModel *model=NULL)
	{
		keys = dynamic_cast <db_key*> (model);
		XcaTreeView::setModel(model);
	}

   public slots:
	void resetOwnPass();
	void setOwnPass();
	void changePin();
	void initPin();
	void changeSoPin();
	void toToken();
};
#endif
