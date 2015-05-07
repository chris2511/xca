/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CERTTREEVIEW_H
#define __CERTTREEVIEW_H

#include "X509SuperTreeView.h"
#include "lib/db_x509.h"

class CertTreeView: public X509SuperTreeView
{
	Q_OBJECT
	db_x509 *certs;

    public:
	CertTreeView(QWidget *parent) : X509SuperTreeView(parent)
	{
		certs = NULL;
	}
	void fillContextMenu(QMenu *menu, QMenu *subExport,
			const QModelIndex &index, QModelIndexList indexes);
	void setModel(db_x509 *model=NULL)
	{
		certs = model;
		X509SuperTreeView::setModel(model);
	}

    public slots:
	void changeView();
	void toRequest();
	void toCertificate();
	void toToken();
	void toOtherToken();
	void genCrl();
	void loadPKCS7();
	void loadPKCS12();
	void deleteFromToken();
	void manageRevocations();
	void certRenewal();
	void caProperties();
	void revoke();
	void unRevoke();
	void setTrust();
};
#endif
