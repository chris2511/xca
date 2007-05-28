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
	QStringList dnl;
	if (!MainWindow::mandatory_dn.isEmpty())
		dnl = MainWindow::mandatory_dn.split(",");

	NIDlist dn_nid = *MainWindow::dn_nid;
	setWindowTitle(tr(XCA_TITLE));
	setupUi(this);

	for (int i=0; i < dn_nid.count(); i++)
		extDNobj->addItem(OBJ_nid2ln(dn_nid[i]));

	for (int i=0; i < dnl.count(); i++) {
		int nid;
		nid = OBJ_sn2nid(CCHAR(dnl[i]));
		extDNlist->insertItem(0, OBJ_nid2ln(nid));
	}
	string_opts << "default" << "nobmp" << "pkix" << "utf8only";
	QStringList s;
	s << tr("Default: automatically detect String type")
	  << tr("NO BMPstrings, only printable and T61")
	  << tr("PKIX recommendation in RFC2459")
	  << tr("UTF8Strings only (RFC2459 recommendation for 2004)");
	mbstring->addItems(s);
}

void Options::on_extDNadd_clicked()
{
	extDNlist->addItem(extDNobj->currentText());
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

void Options::setStringOpt(const QString string_opt)
{
	int index = string_opts.indexOf(string_opt);
	if (index < 0)
		index = 0;
	mbstring->setCurrentIndex(index);
}

QString Options::getStringOpt()
{
	return string_opts[mbstring->currentIndex()];
}

