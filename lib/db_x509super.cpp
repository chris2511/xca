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
#include <QtGui/QMessageBox>

db_x509name::db_x509name(QString db, MainWindow *mw)
	:db_base(db, mw)
{
	allHeaders << new dbheader(HD_subject_name, false, tr("Subject"),
			tr("Complete distinguished name")) <<
		new dbheader(HD_subject_hash, false, tr("Subject hash"),
			tr("Hash to lookup certs in directories"));

	if (dn_translations.size() == 0) {
		dn_translations[NID_countryName] = tr("Country code");
		dn_translations[NID_stateOrProvinceName] = tr("State or Province");
		dn_translations[NID_localityName] = tr("Locality");
		dn_translations[NID_organizationName] = tr("Organisation");
		dn_translations[NID_organizationalUnitName] = tr("Organisational unit");
		dn_translations[NID_commonName] = tr("Common name");
		dn_translations[NID_pkcs9_emailAddress] = tr("E-Mail address");
		dn_translations[NID_serialNumber] = tr("Serial number");
		dn_translations[NID_givenName] = tr("Given name");
		dn_translations[NID_surname] = tr("Surname");
		dn_translations[NID_title] = tr("Title");
		dn_translations[NID_initials] = tr("Initials");
		dn_translations[NID_description] = tr("Description");
		dn_translations[NID_role] = tr("Role");
		dn_translations[NID_pseudonym] = tr("Pseudonym");
		dn_translations[NID_generationQualifier] = tr("Generation Qualifier");
		dn_translations[NID_x500UniqueIdentifier] = tr("x500 Unique Identifier");
		dn_translations[NID_name] = tr("Name");
		dn_translations[NID_dnQualifier] = tr("DN Qualifier");
		dn_translations[NID_pkcs9_unstructuredName] = tr("Unstructured name");
		dn_translations[NID_pkcs9_challengePassword] = tr("Challenge password");

		dn_translations[NID_subject_alt_name] = tr("subject alternative name");
		dn_translations[NID_issuer_alt_name] = tr("issuer alternative name");
		dn_translations[NID_subject_key_identifier] = tr("Subject key identifier");
		dn_translations[NID_authority_key_identifier] = tr("Authority key identifier");
		dn_translations[NID_key_usage] = tr("Key usage");
		dn_translations[NID_ext_key_usage] = tr("Extended key usage");
		dn_translations[NID_crl_distribution_points] = tr("CRL distribution points");
		dn_translations[NID_info_access] = tr("Authority information access");
		dn_translations[NID_netscape_cert_type] = tr("Certificate type");
		dn_translations[NID_netscape_base_url] = tr("Base URL");
		dn_translations[NID_netscape_revocation_url] = tr("Revocation URL");
		dn_translations[NID_netscape_ca_revocation_url] = tr("CA Revocation URL");
		dn_translations[NID_netscape_renewal_url] = tr("Certificate renewal URL");
		dn_translations[NID_netscape_ca_policy_url] = tr("CA policy URL");
		dn_translations[NID_netscape_ssl_server_name] = tr("SSL server name");
		dn_translations[NID_netscape_comment] = tr("Comment");
	}
	foreach(int nid, *MainWindow::dn_nid)
		allHeaders << new dn_dbheader(nid);
}

db_x509super::db_x509super(QString db, MainWindow *mw)
	:db_x509name(db, mw)
{
	NIDlist v3nid;
	v3nid <<
		NID_subject_alt_name <<
		NID_issuer_alt_name <<
		NID_subject_key_identifier <<
		NID_authority_key_identifier <<
		NID_key_usage <<
		NID_ext_key_usage <<
		NID_crl_distribution_points <<
		NID_info_access <<
		NID_netscape_cert_type <<
		NID_netscape_base_url <<
		NID_netscape_revocation_url <<
		NID_netscape_ca_revocation_url <<
		NID_netscape_renewal_url <<
		NID_netscape_ca_policy_url <<
		NID_netscape_ssl_server_name <<
		NID_netscape_comment;

	allHeaders << new dbheader(HD_x509key_name, false, tr("Key name"),
			tr("Internal name of the key"));

	foreach(int nid, v3nid)
		allHeaders << new v3e_dbheader(nid);
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

void db_x509super::extractPubkey()
{
	pki_key *key;
	pki_x509super *pki = static_cast<pki_x509super*>(currentIdx.internalPointer());
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

void db_x509super::toOpenssl() const
{
	pki_x509super *pki = static_cast<pki_x509super*>(currentIdx.internalPointer());
	QString fn = mainwin->getPath() + QDir::separator() +
		pki->getUnderlinedName() + ".conf";
	QString fname = QFileDialog::getSaveFileName(mainwin,
		tr("Save as OpenSSL config"),	fn,
		tr("Config files ( *.conf *.cnf);; All files ( * )"));
	if (fname.isEmpty())
		return;
	fname = QDir::convertSeparators(fname);
	mainwin->setPath(fname.mid(0, fname.lastIndexOf(QRegExp("[/\\\\]")) ));
	pki->opensslConf(fname);
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

