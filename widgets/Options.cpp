/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "Options.h"
#include <openssl/objects.h>

Options::Options(QWidget *parent)
	:QDialog(parent)
{
	NIDlist dn_nid = *MainWindow::dn_nid;
	setWindowTitle(tr(XCA_TITLE));
	setupUi(this);

	for (int i=0; i < dn_nid.count(); i++)
		extDNobj->addItem(OBJ_nid2ln(dn_nid[i]));
}

void Options::on_extDNadd_clicked()
{
	extDNlist->insertItem(0, extDNobj->currentText());
}
void Options::on_extDNdel_clicked()
{
	extDNlist->takeItem(extDNlist->currentRow());
}

QString Options::getDnString()
{
	QStringList dn;
	for (int j=0; j<extDNlist->count(); j++) {
		int nid;
		nid = OBJ_ln2nid(CCHAR(extDNlist->item(j)->text()));
		dn << QString(OBJ_nid2sn(nid));
    }
	return dn.join(",");
}
