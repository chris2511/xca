/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pki_base.h"
#include "pki_temp.h"
#include "db_x509super.h"
#include "database_model.h"
#include "oid.h"

#include "widgets/MainWindow.h"
#include "widgets/CertDetail.h"
#include "widgets/XcaDialog.h"
#include "widgets/XcaWarning.h"

#include <QFileDialog>
#include <QFileInfo>

db_x509name::db_x509name(const char *classname)
	:db_base(classname)
{
}

dbheaderList db_x509name::getHeaders()
{
	dbheaderList h = db_base::getHeaders();
	h <<	new dbheader(HD_subject_name, false, tr("Subject"),
			tr("Complete distinguished name")) <<
		new num_dbheader(HD_subject_hash, false, tr("Subject hash"),
			tr("Hash to lookup certs in directories"));

	foreach(int nid, distname_nid)
		h << new nid_dbheader(nid, dbheader::hd_x509name);
	return h;
}

db_x509super::db_x509super(const char *classname)
	:db_x509name(classname)
{
	pkitype_depends << asym_key << smartCard;
}

void db_x509super::loadContainer()
{
	db_x509name::loadContainer();
	/* Resolve Key references */
	foreach(pki_x509super *pki, Store.getAll<pki_x509super>()) {
		QVariant keySqlId = pki->getKeySqlId();
		if (!keySqlId.isValid())
			continue;
		pki->setRefKey(Store.lookupPki<pki_key>(keySqlId));
	}
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
			tr("Internal name of the key"))
	<<	new dbheader(HD_x509_sigalg, false,
			tr("Signature algorithm"))
	<<	new key_dbheader(HD_key_type, tr("Key type"))
	<<	new key_dbheader(HD_key_size, tr("Key size"))
#ifndef OPENSSL_NO_EC
	<<	new key_dbheader(HD_key_curve, tr("EC Group"))
#endif
	;
	foreach(int nid, v3nid)
		h << new nid_dbheader(nid, dbheader::hd_v3ext);

	foreach(int nid, v3ns_nid)
		h << new nid_dbheader(nid, dbheader::hd_v3ext_ns);
	return h;
}

pki_key *db_x509super::findKey(pki_x509super *ref)
{
	db_key *keys = Database.model<db_key>();
	pki_key *key, *refkey;
	if (!ref)
		return NULL;
	if ((key = ref->getRefKey()) != NULL )
		return key;
	refkey = ref->getPubKey();
	if (!refkey)
		return NULL;
	key = dynamic_cast<pki_key *>(keys->getByReference(refkey));
	ref->setRefKey(key);
	delete refkey;
	return key;
}

QList<pki_x509super *> db_x509super::findByPubKey(pki_key *refkey)
{
	QList<pki_x509super *> list;
	foreach(pki_x509super *pki, Store.getAll<pki_x509super>()) {
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
	db_key *keys = Database.model<db_key>();
	pki_key *key;
	pki_x509super *pki = fromIndex<pki_x509super>(index);
	if (!pki)
		return;
	key = pki->getPubKey();
	if (!key)
		return;
	key->setIntName(pki->getIntName());
	key->pkiSource = transformed;
	key->selfComment(tr("Extracted from %1 '%2'")
		.arg(pki->getType() == x509 ?
			tr("Certificate") : tr("Certificate request"))
		.arg(pki->getIntName()));
	key = dynamic_cast<pki_key*>(keys->insert(key));
	if (!key)
		return;
	if (Settings["suppress_messages"])
		return;
	XCA_INFO(key->getMsg(pki_base::msg_import).arg(pki->getIntName()));
}

void db_x509super::toOpenssl(QModelIndex index) const
{
	pki_x509super *pki = fromIndex<pki_x509super>(index);
	QString fn = Settings["workingdir"] + pki->getUnderlinedName() + ".conf";
	QString fname = QFileDialog::getSaveFileName(NULL,
		tr("Save as OpenSSL config"),	fn,
		tr("Config files ( *.conf *.cnf);; All files ( * )"));
	if (fname.isEmpty())
		return;

	update_workingdir(fname);
	pki->opensslConf(fname);
}

void db_x509super::toTemplate(QModelIndex index)
{
	db_temp *temps = Database.model<db_temp>();
	pki_x509super *pki = fromIndex<pki_x509super>(index);
	if (!pki || !temps)
		return;

	try {
		pki_temp *temp = new pki_temp();
		check_oom(temp);
		temp->setIntName(pki->getIntName());
		extList el = temp->fromCert(pki);
		if (el.size()) {
			QString etext;
			etext = QString("<h3>") +
				tr("The following extensions were not ported into the template") +
				QString("</h3><hr>") +
				el.getHtml("<br>");
			QTextEdit *textbox = new QTextEdit(etext);
		        XcaDialog *d = new XcaDialog(NULL, x509, textbox,
						QString(), QString());
			d->aboutDialog(QPixmap(":tempImg"));
		        d->exec();
		        delete d;
		}
		temp->pkiSource = transformed;
		temp->selfComment(tr("Transformed from %1 '%2'")
			.arg(pki->getType() == x509 ?
				tr("Certificate") : tr("Certificate request"))
			.arg(pki->getIntName()));
		createSuccess(temps->insert(temp));
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
}
