/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __TEMPTREEVIEW_H
#define __TEMPTREEVIEW_H

#include "XcaTreeView.h"
#include "lib/db_temp.h"

class TempTreeView: public XcaTreeView
{
	Q_OBJECT
	db_temp *temps;

    public:
	TempTreeView(QWidget *parent) : XcaTreeView(parent)
	{
		temps = NULL;
	}
	void fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes);
	void setModel(db_temp *model=NULL)
	{
		temps = model;
		XcaTreeView::setModel(model);
	}

   public slots:
	void certFromTemp();
	void reqFromTemp();
	void duplicateTemp();
    signals:
	void newReq(pki_temp *);
	void newCert(pki_temp *);
};
#endif
