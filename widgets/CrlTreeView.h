/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2006 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CRLTREEVIEW_H
#define __CRLTREEVIEW_H

#include "XcaTreeView.h"
#include "lib/db_crl.h"

class pki_x509;

class CrlTreeView: public XcaTreeView
{
	Q_OBJECT

	db_crl *crls() const
	{
		return dynamic_cast<db_crl*>(basemodel);
	}

    public:
	CrlTreeView(QWidget *parent) : XcaTreeView(parent) { }
	void showPki(pki_base *pki);

    public slots:
	void newItem(pki_x509 *cert);
	void newItem();
};
#endif
