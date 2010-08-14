/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/func.h"
#include "Options.h"
#include "lib/pki_scard.h"
#include <openssl/objects.h>
#include <QtGui/QMessageBox>

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
	string_opts << "MASK:0x2002" << "pkix" << "nombstr" <<
			"utf8only" << "default";
	QStringList s;
	s << tr("Printable string or UTF8 (default)")
	  << tr("PKIX recommendation in RFC2459")
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

void Options::on_addButton_clicked(void)
{
	load_pkcs11 l;
	pkcs11_lib *lib;
	QString fname, status;

	fname = QFileDialog::getOpenFileName(this, l.caption,
		getLibDir(), l.filter);

	if (fname.isEmpty() || pkcs11::get_lib(fname))
		return;
	try {
		lib = pkcs11::load_lib(fname, false);
		if (lib)
			status = lib->driverInfo();
	} catch (errorEx &ex) {
		lib = NULL;
		status = ex.getString();
	}
	QListWidgetItem *item = new QListWidgetItem(fname);
	item->setToolTip(status);
	if (lib)
		item->setIcon(*MainWindow::doneIco);
	pkcs11List->addItem(item);
}

void Options::on_removeButton_clicked(void)
{
	QListWidgetItem *item = pkcs11List->takeItem(pkcs11List->currentRow());
	if (!item)
		return;
	try {
		pkcs11::remove_lib(item->text());
	} catch (errorEx &err) {
		mw->Error(err);
	}
}

void Options::setupPkcs11Provider(QString list)
{
	pkcs11::load_libs(list, true);
	pkcs11_lib_list libs = pkcs11::get_libs();

	foreach(pkcs11_lib *l, libs) {
		QListWidgetItem *item = new QListWidgetItem(l->filename());
		item->setIcon(*MainWindow::doneIco);
		item->setToolTip(l->driverInfo());
		pkcs11List->addItem(item);
	}
	foreach(QString libname, list.split('\n')) {
		if (libs.get_lib(libname))
			continue;
		QListWidgetItem *item = new QListWidgetItem(libname);
		item->setToolTip(tr("Load failed"));
		pkcs11List->addItem(item);
	}
}

QString Options::getPkcs11Provider()
{
	QStringList prov;
	for (int j=0; j<pkcs11List->count(); j++) {
		prov << pkcs11List->item(j)->text();
	}
	return prov.join("\n");
}
