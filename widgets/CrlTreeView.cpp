/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2019 - 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "CrlTreeView.h"
#include "CrlDetail.h"
#include "CrlDetail.h"
#include "MainWindow.h"
#include "lib/db_crl.h"
#include "lib/database_model.h"

void CrlTreeView::showPki(pki_base *pki) const
{
	db_x509 *certs = models()->model<db_x509>();
	db_crl *crls = dynamic_cast<db_crl*>(basemodel);
	pki_crl *crl = dynamic_cast<pki_crl *>(pki);

	if (!crl || !crls || !certs)
		return;

	CrlDetail *dlg = new CrlDetail(NULL);
	if (!dlg)
		return;

	dlg->setCrl(crl);
	connect(dlg->issuerIntName, SIGNAL(doubleClicked(QString)),
		mainwin->certView, SLOT(showItem(QString)));
	connect(certs, SIGNAL(pkiChanged(pki_base*)),
		dlg, SLOT(itemChanged(pki_base*)));
	if (dlg->exec()) {
		crls->updateItem(pki, dlg->descr->text(),
					dlg->comment->toPlainText());
	}
	delete dlg;
}
