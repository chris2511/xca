/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2019 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "CrlTreeView.h"
#include "CrlDetail.h"
#include "NewCrl.h"
#include "XcaDialog.h"
#include "MainWindow.h"
#include "ItemCombo.h"
#include "XcaWarning.h"
#include "lib/db_crl.h"
#include "lib/pki_x509.h"
#include "lib/database_model.h"

void CrlTreeView::showPki(pki_base *pki)
{
	CrlDetail::showCrl(this, dynamic_cast<pki_crl*>(pki));
}

void CrlTreeView::newItem(pki_x509 *cert)
{
	NewCrl::newCrl(this, cert);
}

void CrlTreeView::newItem()
{
	db_x509 *certs = Database.model<db_x509>();
	QList<pki_x509 *> cas = certs->getAllIssuers();
	pki_x509 *ca = NULL;

	switch (cas.size()) {
	case 0:
		XCA_INFO(tr("There are no CA certificates for CRL generation"));
		return;
	case 1:
		ca = cas[0];
		break;
	default: {
		itemComboCert *c = new itemComboCert(NULL);
		XcaDialog *d = new XcaDialog(this, revocation, c,
			tr("Select CA certificate"), QString());
		c->insertPkiItems(cas);
		if (!d->exec()) {
			delete d;
			return;
		}
		ca = c->currentPkiItem();
		delete d;
		}
	}
	newItem(ca);
}

