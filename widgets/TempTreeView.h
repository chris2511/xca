/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2020 Christian Hohnstaedt.
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

	db_temp *temps() const
	{
		return dynamic_cast<db_temp*>(basemodel);
	}

	bool runTempDlg(pki_temp *temp);

    public:
	TempTreeView(QWidget *parent) : XcaTreeView(parent) { }
	void fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes);
	void showPki(pki_base *pki);
	bool alterTemp(pki_temp *temp);

   public slots:
	void certFromTemp();
	void reqFromTemp();
	void duplicateTemp();
	void newItem();

    signals:
	void newReq(pki_temp *);
	void newCert(pki_temp *);
};
#endif
