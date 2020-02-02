/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __REQTREEVIEW_H
#define __REQTREEVIEW_H

#include "X509SuperTreeView.h"
#include "lib/db_x509req.h"
#include "lib/database_model.h"

class ReqTreeView: public X509SuperTreeView
{
	Q_OBJECT
	db_x509req *reqs;

    public:
	ReqTreeView(QWidget *parent) : X509SuperTreeView(parent)
	{
		reqs = NULL;
	}
	void fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes);
	void setModels(database_model *models)
	{
		reqs = models->model<db_x509req>();
		X509SuperTreeView::setModel(reqs);
	}

    public slots:
	void toRequest();
	void signReq();
	void markSigned();
	void unmarkSigned();
};
#endif
