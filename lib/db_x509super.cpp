/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pki_base.h"
#include "db_x509super.h"
#include "widgets/MainWindow.h"
#include "ui_About.h"
#include "oid.h"
#include <QMessageBox>

db_x509name::db_x509name(QString db, MainWindow *mw)
	:db_base(db, mw)
{
}

dbheaderList db_x509name::getHeaders()
{
	dbheaderList h = db_base::getHeaders();
	h <<	new dbheader(HD_subject_name, false, tr("Subject"),
			tr("Complete distinguished name")) <<
		new dbheader(HD_subject_hash, false, tr("Subject hash"),
			tr("Hash to lookup certs in directories"));

	foreach(int nid, *MainWindow::dn_nid)
		h << new nid_dbheader(nid, dbheader::hd_x509name);
	return h;
}

db_x509super::db_x509super(QString db, MainWindow *mw)
	:db_x509name(db, mw)
{
}

dbheaderList db_x509super::getHeaders()
{
	dbheaderList h = db_x509name::getHeaders();
	NIDlist v3nid, v3ns_nid;
	v3nid <<
		NID_subject_alt_name <<
		NID_issuer_alt_name <<
		NID_subject_key_identifier <<
		NID_authority_key_identifier <<
		NID_key_usage <<
		NID_ext_key_usage <<
		NID_crl_distribution_points <<
		NID_info_access;
	v3ns_nid <<
		NID_netscape_cert_type <<
		NID_netscape_base_url <<
		NID_netscape_revocation_url <<
		NID_netscape_ca_revocation_url <<
		NID_netscape_renewal_url <<
		NID_netscape_ca_policy_url <<
		NID_netscape_ssl_server_name <<
		NID_netscape_comment;

	h <<	new dbheader(HD_x509key_name, false, tr("Key name"),
			tr("Internal name of the key")) <<
		new dbheader(HD_x509_sigalg, false, tr("Signature Algorithm"));


	foreach(int nid, v3nid)
		h << new nid_dbheader(nid, dbheader::hd_v3ext);

	foreach(int nid, v3ns_nid)
		h << new nid_dbheader(nid, dbheader::hd_v3ext_ns);
	return h;
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
	ref->setRefKey(key);
	delete(refkey);

	return key;
}

QList<pki_x509super *> db_x509super::findByPubKey(pki_key *refkey)
{
	QList<pki_x509super *> list;
	FOR_ALL_pki(pki, pki_x509super) {
		pki_key *key = pki->getPubKey();
		if (!key)
			continue;
		if (refkey->compare(key))
			list << pki;
		delete key;
	}
	return list;
}

void db_x509super::extractPubkey(QModelIndex index)
{
	pki_key *key;
	pki_x509super *pki = static_cast<pki_x509super*>
				(index.internalPointer());
	if (!pki)
		return;
	key = pki->getPubKey();
	if (!key)
		return;
	key->setIntName(pki->getIntName());
	key = (pki_key*)mainwin->keys->insert(key);
	if (!key)
		return;
	if (pki_base::suppress_messages)
		return;
	XCA_INFO(key->getMsg(pki_base::msg_import).arg(pki->getIntName()));
}

void db_x509super::toOpenssl(QModelIndex index) const
{
	pki_x509super *pki = static_cast<pki_x509super*>(index.internalPointer());
	QString fn = mainwin->getPath() + QDir::separator() +
		pki->getUnderlinedName() + ".conf";
	QString fname = QFileDialog::getSaveFileName(mainwin,
		tr("Save as OpenSSL config"),	fn,
		tr("Config files ( *.conf *.cnf);; All files ( * )"));
	if (fname.isEmpty())
		return;
	fname = nativeSeparator(fname);
	mainwin->setPath(fname.mid(0, fname.lastIndexOf(QRegExp("[/\\\\]")) ));
	pki->opensslConf(fname);
}

void db_x509super::toTemplate(QModelIndex index)
{
	pki_x509super *pki = static_cast<pki_x509super*>(index.internalPointer());
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

