/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "lib/func.h"
#include "Options.h"
#include "SearchPkcs11.h"
#include "lib/pki_scard.h"
#include <openssl/objects.h>
#include <QtGui/QMessageBox>
#include <QtGui/QToolTip>

Options::Options(MainWindow *parent)
	:QDialog(parent)
{
	mw = parent;

	NIDlist dn_nid = *MainWindow::dn_nid;
	setWindowTitle(tr(XCA_TITLE));
	setupUi(this);

	for (int i=0; i < dn_nid.count(); i++)
		extDNobj->addItem(OBJ_nid2ln(dn_nid[i]));

	string_opts << "MASK:0x2002" << "pkix" << "nombstr" <<
			"utf8only" << "default";
	QStringList s;
	s << tr("Printable string or UTF8 (default)")
	  << tr("PKIX recommendation in RFC2459")
	  << tr("No BMP strings, only printable and T61")
	  << tr("UTF8 strings only (RFC2459)")
	  << tr("All strings");
	mbstring->addItems(s);
	searchP11 = NULL;
}

Options::~Options()
{
	if (searchP11)
		delete searchP11;
}

void Options::on_extDNadd_clicked()
{
	extDNlist->addItem(extDNobj->currentText());
}
void Options::on_extDNdel_clicked()
{
	extDNlist->takeItem(extDNlist->currentRow());
}

void Options::setDnString(QString dn)
{
	QStringList dnl;

	if (!dn.isEmpty())
		dnl = dn.split(",");
	for (int i=0; i < dnl.count(); i++) {
		int nid = OBJ_sn2nid(CCHAR(dnl[i]));
		extDNlist->insertItem(0, OBJ_nid2ln(nid));
	}
}

QString Options::getDnString()
{
	QStringList dn;

	for (int j=0; j<extDNlist->count(); j++) {
		int nid = OBJ_ln2nid(CCHAR(extDNlist->item(j)->text()));
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
	QString fname;

	fname = QFileDialog::getOpenFileName(this, l.caption,
		getLibDir(), l.filter);

	addLib(fname);
}

void Options::addLib(QString fname)
{
	pkcs11_lib *lib;
	QString status;

	fname = QFileInfo(fname).canonicalFilePath();

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
	status = status.trimmed();
	QListWidgetItem *item = new QListWidgetItem(fname);
	item->setToolTip(status);
	if (lib)
		item->setIcon(*MainWindow::doneIco);
	pkcs11List->addItem(item);
	if (searchP11)
		QToolTip::showText(searchP11->mapToGlobal(
			QPoint(0,0)), status);
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

void Options::on_searchPkcs11_clicked(void)
{
	if (!searchP11) {
		searchP11 = new SearchPkcs11(this, QString());
		connect(searchP11, SIGNAL(addLib(QString)),
			this, SLOT(addLib(QString)));
	}
	searchP11->show();
}

void Options::setupPkcs11Provider(QString list)
{
	pkcs11_lib_list libs = pkcs11::get_libs();

	foreach(pkcs11_lib *l, libs) {
		QListWidgetItem *item = new QListWidgetItem(l->filename());
		try {
			item->setToolTip(l->driverInfo());
			item->setIcon(*MainWindow::doneIco);
		} catch (errorEx &err) {
			mw->Error(err);
		}
		pkcs11List->addItem(item);
	}
	if (!list.isEmpty()) {
		foreach(QString libname, list.split('\n')) {
			if (libs.get_lib(libname))
				continue;
			QListWidgetItem *item = new QListWidgetItem(libname);
			item->setToolTip(tr("Load failed"));
			pkcs11List->addItem(item);
		}
	}
}

QString Options::getPkcs11Provider()
{
	QStringList prov;
	for (int j=0; j<pkcs11List->count(); j++) {
		prov << pkcs11List->item(j)->text();
	}
	if (prov.count() == 0)
		return QString("");
	return prov.join("\n");
}
