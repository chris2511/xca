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

	db_key *keys() const
	{
		return dynamic_cast<db_key*>(basemodel);
	}

    public:
	KeyTreeView(QWidget *parent) : XcaTreeView(parent) { }
	void fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes);
	void showPki(pki_base *pki);

   public slots:
	void resetOwnPass();
	void setOwnPass();
	void changePin();
	void initPin();
	void changeSoPin();
	void toToken();
	void newItem();
	void newItem(const QString &name);
};
#endif
