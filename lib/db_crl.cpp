/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_crl.h"
#include "db_x509.h"
#include "main.h"
#include "exception.h"
#include "database_model.h"
#include <QMessageBox>
#include <QContextMenuEvent>
#include "widgets/ItemCombo.h"

db_crl::db_crl() : db_x509name("crls")
{
	sqlHashTable = "crls";
	pkitype << revocation;
	pkitype_depends << x509;
	updateHeaders();
	loadContainer();
}

dbheaderList db_crl::getHeaders()
{
	dbheaderList h = db_x509name::getHeaders();
	h <<	new dbheader(HD_crl_signer, true, tr("Signer"),
			tr("Internal name of the signer")) <<
		new num_dbheader(HD_crl_revoked, true, tr("No. revoked"),
			tr("Number of revoked certificates")) <<
		new date_dbheader(HD_crl_lastUpdate,false, tr("Last update")) <<
		new date_dbheader(HD_crl_nextUpdate, true, tr("Next update")) <<
		new num_dbheader(HD_crl_crlnumber, false, tr("CRL number"));
	return h;
}

pki_base *db_crl::newPKI(enum pki_type type)
{
	(void)type;
	return new pki_crl();
}

void db_crl::load()
{
	load_crl l;
	load_default(l);
}

void db_crl::revokeCerts(pki_crl *crl)
{
	db_x509 *certs = Database.model<db_x509>();
	x509revList revlist;

	if (!certs || !crl)
		return;

	pki_x509 *signer = crl->getIssuer();
	if (!signer)
		return;

	revlist = crl->getRevList();
	signer->mergeRevList(revlist);
	foreach(x509rev revok, revlist) {
		pki_x509 *crt = signer->getBySerial(revok.getSerial());
		if (crt)
			crt->setRevoked(revok);
	}
}

void db_crl::removeSigner(pki_base *signer)
{
	foreach(pki_crl *crl, Store.getAll<pki_crl>()) {
		if (crl->getIssuer() == signer) {
			crl->setIssuer(NULL);
		}
	}
}

void db_crl::inToCont(pki_base *pki)
{
	pki_crl *crl = dynamic_cast<pki_crl *>(pki);
	unsigned hash = crl->getSubject().hashNum();
	QList<pki_x509 *> items;

	items = Store.sqlSELECTpki<pki_x509>(
		"SELECT x509super.item FROM x509super "
		"JOIN certs ON certs.item = x509super.item "
		"WHERE x509super.subj_hash=? AND certs.ca=1",
			QList<QVariant>() << QVariant(hash));
	foreach(pki_x509 *x, items) {
		qDebug() << "Possible Crl issuer:" << x->getIntName();
		crl->verify(x);
	}
	db_base::inToCont(pki);
}

pki_base *db_crl::insert(pki_base *item)
{
	pki_crl *crl = dynamic_cast<pki_crl *>(item);
	pki_crl *oldcrl = dynamic_cast<pki_crl *>(getByReference(crl));
	if (oldcrl) {
		XCA_INFO(tr("The revocation list already exists in the database as:\n'%1'\nand so it was not imported").arg(oldcrl->getIntName()));
		delete(crl);
		return NULL;
	}
	Transaction;
	if (TransBegin()) {
		crl = dynamic_cast<pki_crl *>(insertPKI(crl));
		if (crl) {
			revokeCerts(crl);
			TransCommit();
		}
	}
	return crl;
}

void db_crl::store(QModelIndex index)
{
	pki_crl *crl = fromIndex<pki_crl>(index);

	if (!index.isValid() || !crl)
		return;

	QList<exportType> types; types <<
		exportType(exportType::PEM, "pem", "PEM") <<
		exportType(exportType::DER, "der", "DER") <<
		exportType(exportType::vcalendar, "ics", "vCalendar");
	ExportDialog *dlg = new ExportDialog(NULL,
			tr("Revocation list export"),
			tr("CRL ( *.pem *.der *.crl )"), crl,
			QPixmap(":revImg"), types);
	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	try {
		XFile file(dlg->filename->text());
		pki_base::pem_comment = dlg->pemComment->isChecked();
		file.open_key();
		if (dlg->type() == exportType::vcalendar) {
			writeVcalendar(file, crl->icsVEVENT());
		} else {
			crl->writeCrl(file, dlg->type() == exportType::PEM);
		}
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
	pki_base::pem_comment = false;
	delete dlg;
}

pki_crl *db_crl::newCrl(const crljob &task)
{
	pki_crl *crl = NULL;
	pki_x509 *cert = task.issuer;
	QSqlDatabase db = QSqlDatabase::database();
	try {
		x509v3ext e;
		X509V3_CTX ext_ctx;
		X509V3_set_ctx(&ext_ctx, cert->getCert(), NULL, NULL, NULL, 0);
		X509V3_set_ctx_nodb(&ext_ctx);
		XSqlQuery q;

		crl = new pki_crl();
		crl->createCrl(cert->getIntName(), cert);
		crl->pkiSource = generated;

		foreach(x509rev rev, cert->getRevList())
			crl->addRev(rev, task.withReason);

		if (task.authKeyId) {
			crl->addV3ext(e.create(NID_authority_key_identifier,
				"keyid,issuer", &ext_ctx));
		}
		if (task.subAltName) {
			if (cert->hasExtension(NID_subject_alt_name)) {
				crl->addV3ext(e.create(NID_issuer_alt_name,
					"issuer:copy", &ext_ctx));
			}
		}
		if (task.setCrlNumber) {
			crl->setCrlNumber(task.crlNumber);
			cert->setCrlNumber(task.crlNumber);
		}
		crl->setIssuer(cert);
		crl->setLastUpdate(task.lastUpdate);
		crl->setNextUpdate(task.nextUpdate);
		crl->sign(cert->getRefKey(), task.hashAlgo);

		Transaction;
		if (!TransBegin())
			throw errorEx(tr("Failed to initiate DB transaction"));
		cert->setCrlExpire(task.nextUpdate);
		SQL_PREPARE(q, "UPDATE authority set crlNo=?, crlExpire=? WHERE item=?");
		q.bindValue(0, (uint)cert->getCrlNumber().getLong());
		q.bindValue(1, task.nextUpdate.toPlain());
		q.bindValue(2, cert->getSqlItemId());
		AffectedItems(cert->getSqlItemId());
		q.exec();
		QSqlError err = q.lastError();
		if (err.isValid())
			throw errorEx(tr("Database error: %1").arg(err.text()));
		SQL_PREPARE(q, "UPDATE revocations set crlNo=? "
				"WHERE crlNo IS NULL AND caId=?");
		q.bindValue(0, (uint)crl->getCrlNumber().getLong());
		q.bindValue(1, cert->getSqlItemId());
		q.exec();
		err = q.lastError();
		if (err.isValid())
			throw errorEx(tr("Database error: %1").arg(err.text()));
		crl = dynamic_cast<pki_crl *>(insertPKI(crl));
		err = db.lastError();
		if (err.isValid())
			throw errorEx(tr("Database error: %1").arg(err.text()));
		TransCommit();
		createSuccess(crl);
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
		delete crl;
		crl = NULL;
	}
	return crl;
}
