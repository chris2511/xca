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
#include "lib/database_model.h"

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
	void setModels(database_model *models)
	{
		keys = models->model<db_key>();
		XcaTreeView::setModel(keys);
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
