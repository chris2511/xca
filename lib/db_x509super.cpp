/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "db_x509super.h"
#include "widgets/MainWindow.h"
#include "ui_About.h"

db_x509super::db_x509super(QString db, MainWindow *mw)
	:db_base(db, mw)
{
}

void db_x509super::delKey(pki_key *delkey)
{
	FOR_ALL_pki(pki, pki_x509super) { pki->delRefKey(delkey); }
}

void db_x509super::newKey(pki_key *newkey)
{
	 FOR_ALL_pki(pki,pki_x509super) { pki->setRefKey(newkey); }
}

pki_key *db_x509super::findKey(pki_x509super *ref)
{
	pki_key *key, *refkey;
	if (!ref)
		return NULL;
	if ((key = ref->getRefKey()) != NULL )
		return key;
	refkey = ref->getPubKey();
	if (!refkey)
		return NULL;
	key = (pki_key *)mainwin->keys->getByReference(refkey);
	if (key && key->isPubKey()) {
		key = NULL;
	} else {
		ref->setRefKey(key);
	}
	if (refkey)
		delete(refkey);
	return key;
}

pki_x509super *db_x509super::findByByPubKey(pki_key *refkey)
{
	FOR_ALL_pki(pki, pki_x509super) {
		pki_key *key = pki->getPubKey();
		if (!key)
			continue;
		bool match = refkey->compare(key);
		delete key;
		if (match)
			return pki;
	}
	return NULL;
}

void db_x509super::toTemplate()
{
	pki_x509super *pki = static_cast<pki_x509super*>(currentIdx.internalPointer());
	if (!pki)
		return;

	try {
		pki_temp *temp = new pki_temp();
		check_oom(temp);
		temp->setIntName(pki->getIntName());
		extList el = temp->fromCert(pki);
		if (el.size()) {
			Ui::About ui;
			QString etext;
		        QDialog *d = new QDialog(mainwin, 0);
		        ui.setupUi(d);
			etext = QString("<h3>") +
				tr("The following extensions were not ported into the template") +
				QString("</h3><hr>") +
				el.getHtml("<br>");
			ui.textbox->setHtml(etext);
			d->setWindowTitle(XCA_TITLE);
			ui.image->setPixmap(*MainWindow::tempImg);
			ui.image1->setPixmap(*MainWindow::certImg);
		        d->exec();
		        delete d;
		}
		createSuccess(mainwin->temps->insert(temp));
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
}

