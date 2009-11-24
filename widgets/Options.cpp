/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2009 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "Options.h"
#include "lib/pki_scard.h"
#include <openssl/objects.h>
#include <qmessagebox.h>

Options::Options(MainWindow *parent)
	:QDialog(parent)
{
	mw = parent;
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
	string_opts << "pkix" << "nombstr" << "utf8only" << "default";
	QStringList s;
	s << tr("PKIX recommendation in RFC2459 (default)")
	  << tr("No BMP strings, only printable and T61")
	  << tr("UTF8 strings only (RFC2459)")
	  << tr("All strings");
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

void Options::on_fileButton_clicked(void)
{
	load_pkcs11 l;
	QString fname;

	fname = QFileDialog::getOpenFileName(this, l.caption,
		pkcs11path->text(), l.filter);

	if (fname.isEmpty())
		return;
	pkcs11path->setText(fname);
}


void Options::on_tryLoadButton_clicked(void)
{
	try {
		QString lib = pkcs11path->text();
		pki_scard::init_p11engine(lib, false);
		pkcs11 p11;
		p11.getSlotList();
		if (!lib.isEmpty()) {
			QMessageBox::information(this, XCA_TITLE,
				tr("Successfully loaded PKCS#11 library: ") + lib,
				tr("Ok"));
		}
	} catch (errorEx &err) {
		mw->Error(err);
	}
}
