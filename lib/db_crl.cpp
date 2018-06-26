/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_crl.h"
#include "exception.h"
#include "widgets/MainWindow.h"
#include "widgets/CrlDetail.h"
#include "widgets/NewCrl.h"
#include <QMessageBox>
#include <QContextMenuEvent>
#include "widgets/XcaDialog.h"
#include "widgets/ItemCombo.h"
#include "ui_NewCrl.h"

db_crl::db_crl(MainWindow *mw)
	:db_x509name(mw)
{
	class_name = "crls";
	sqlHashTable = "crls";
	pkitype << revocation;
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
	x509revList revlist;

	if (!mainwin->certs)
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
	FOR_ALL_pki(crl, pki_crl) {
		if (crl->getIssuer() == signer) {
			crl->setIssuer(NULL);
		}
	}
}

void db_crl::inToCont(pki_base *pki)
{
	pki_crl *crl = static_cast<pki_crl *>(pki);
	unsigned hash = crl->getSubject().hashNum();
	QList<pki_x509 *> items;

	items = sqlSELECTpki<pki_x509>(
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
	pki_crl *crl = static_cast<pki_crl *>(item);
	pki_crl *oldcrl = dynamic_cast<pki_crl *>(getByReference(crl));
	if (oldcrl) {
		XCA_INFO(tr("The revocation list already exists in the database as:\n'%1'\nand so it was not imported").arg(oldcrl->getIntName()));
		delete(crl);
		return NULL;
	}
	Transaction;
	if (TransBegin()) {
		insertPKI(crl);
		revokeCerts(crl);
		TransCommit();
	}
	return crl;
}

void db_crl::showPki(pki_base *pki)
{
	pki_crl *crl = dynamic_cast<pki_crl *>(pki);
	if (!crl)
		return;
	CrlDetail *dlg = new CrlDetail(mainwin);
	if (!dlg)
		return;

	dlg->setCrl(crl);
	connect(dlg->issuerIntName, SIGNAL(doubleClicked(QString)),
		mainwin->certs, SLOT(showItem(QString)));
	connect(mainwin->certs, SIGNAL(pkiChanged(pki_base*)),
		dlg, SLOT(itemChanged(pki_base*)));
	if (dlg->exec()) {
		QString newname = dlg->descr->text();
		QString newcomment = dlg->comment->toPlainText();
		if (newname != pki->getIntName() ||
		    newcomment != pki->getComment())
		{
			updateItem(pki, newname, newcomment);
		}
	}
	delete dlg;
}

void db_crl::store(QModelIndex index)
{
	QList<exportType> types;

	if (!index.isValid())
		return;
	pki_crl *crl = static_cast<pki_crl*>(index.internalPointer());
	if (!crl)
		return;

	types <<
		exportType(exportType::PEM, "pem", "PEM") <<
		exportType(exportType::DER, "der", "DER") <<
		exportType(exportType::vcalendar, "ics", "vCalendar");
	ExportDialog *dlg = new ExportDialog(mainwin,
			tr("Revocation list export"),
			tr("CRL ( *.pem *.der *.crl )"), crl,
			MainWindow::revImg, types);
	if (!dlg->exec()) {
		delete dlg;
		return;
	}
	QString fname = dlg->filename->text();

	try {
		if (dlg->type() == exportType::vcalendar) {
			writeVcalendar(fname, crl->icsVEVENT());
		} else {
			crl->writeCrl(fname, dlg->type() == exportType::PEM);
		}
	}
	catch (errorEx &err) {
		mainwin->Error(err);
	}
	delete dlg;
}

#if 0
void db_crl::updateRevocations(pki_x509 *cert)
{
	x509name issname = cert->getSubject();
	x509revList revlist;
	pki_crl *latest = NULL;

	FOR_ALL_pki(crl, pki_crl) {
		if (!(issname == crl->getSubject()))
			continue;
		pki_key *key = cert->getPubKey();
		if (!key)
			continue;
		if (!crl->verify(key)) {
			delete key;
			continue;
		}
		delete key;
		pki_x509 *old = crl->getIssuer();
		if (!old) {
			crl->setIssuer(cert);
		} else if (old != cert) {
			if (old->getNotAfter() < cert->getNotAfter())
				crl->setIssuer(cert);
		}
		if (!latest || (latest->getCrlNumber() < crl->getCrlNumber()))
			latest = crl;
	}
	if (latest) {
		revlist = latest->getRevList();
		cert->mergeRevList(revlist);
		cert->setCrlNumber(latest->getCrlNumber());
	}
}
#endif

void db_crl::newItem()
{
	QList<pki_x509 *> cas = mainwin->certs->getAllIssuers();
	pki_x509 *ca = NULL;

	switch (cas.size()) {
	case 0:
		XCA_INFO(tr("There are no CA certificates for CRL generation"));
		return;
	case 1:
		ca = cas[0];
		break;
	default: {
		itemComboCert *c = new itemComboCert(NULL);
		XcaDialog *d = new XcaDialog(mainwin, revocation, c,
			tr("Select CA certificate"), QString());
		c->insertPkiItems(cas);
		if (!d->exec()) {
			delete d;
			return;
		}
		ca = c->currentPkiItem();
		delete d;
		}
	}
	newItem(ca);
}

void db_crl::newItem(pki_x509 *cert)
{
	if (!cert)
		return;

	pki_crl *crl = NULL;
	NewCrl *widget = new NewCrl(NULL, cert);
	XcaDialog *dlg = new XcaDialog(mainwin, revocation, widget,
					tr("Create CRL"), QString());
	if (!dlg->exec()) {
		delete dlg;
		return;
	}
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

		bool withReason = widget->revocationReasons->isChecked();
		foreach(x509rev rev, cert->getRevList())
			crl->addRev(rev, withReason);

		if (widget->authKeyId->isChecked()) {
			crl->addV3ext(e.create(NID_authority_key_identifier,
				"keyid,issuer", &ext_ctx));
		}
		if (widget->subAltName->isChecked()) {
			if (cert->hasExtension(NID_subject_alt_name)) {
				crl->addV3ext(e.create(NID_issuer_alt_name,
					"issuer:copy", &ext_ctx));
			}
		}
		if (widget->setCrlNumber->isChecked()) {
			a1int num;
			num.setDec(widget->crlNumber->text());
			crl->setCrlNumber(num);
			cert->setCrlNumber(num);
		}
		crl->setIssuer(cert);
		crl->setLastUpdate(widget->lastUpdate->getDate());
		crl->setNextUpdate(widget->nextUpdate->getDate());
		crl->sign(cert->getRefKey(), widget->hashAlgo->currentHash());

		Transaction;
		if (!TransBegin())
			throw errorEx(tr("Failed to initiate DB transaction"));
		cert->setCrlExpire(widget->nextUpdate->getDate());
		SQL_PREPARE(q, "UPDATE authority set crlNo=?, crlExpire=? WHERE item=?");
		q.bindValue(0, (uint)cert->getCrlNumber().getLong());
		q.bindValue(1, widget->nextUpdate->getDate().toPlain());
		q.bindValue(2, cert->getSqlItemId());
		AffectedItems(cert->getSqlItemId());
		q.exec();
		QSqlError err = q.lastError();
		if (err.isValid())
			throw errorEx(tr("Database error: ").arg(err.text()));
		SQL_PREPARE(q, "UPDATE revocations set crlNo=? "
				"WHERE crlNo IS NULL AND caId=?");
		q.bindValue(0, (uint)crl->getCrlNumber().getLong());
		q.bindValue(1, cert->getSqlItemId());
		q.exec();
		err = q.lastError();
		if (err.isValid())
			throw errorEx(tr("Database error: ").arg(err.text()));
		insertPKI(crl);
		err = db.lastError();
		if (err.isValid())
			throw errorEx(tr("Database error: ").arg(err.text()));
		TransCommit();
		createSuccess((crl));
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
		if (crl)
			delete crl;
		crl = NULL;
	}
	delete dlg;
	return;
}
