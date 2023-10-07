/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "CrlDetail.h"
#include "CertDetail.h"
#include "MainWindow.h"
#include "Help.h"
#include "distname.h"
#include "clicklabel.h"
#include "RevocationList.h"
#include "OpenDb.h"
#include "OidResolver.h"
#include "lib/pki_crl.h"
#include <QLabel>
#include <QTextEdit>
#include <QLineEdit>

CrlDetail::CrlDetail(QWidget *w) : XcaDetail(w)
{
	setupUi(this);
	init("crldetail", ":revImg");
}

void CrlDetail::setCrl(pki_crl *crl)
{
	pki_x509 *iss;
	x509v3ext e1, e2;

	connect_pki(crl);
	iss = crl->getIssuer();
	crlSqlId = crl->getSqlItemId();

	signCheck->disableToolTip();
	signCheck->setClickText(crl->getSigAlg());
	if (iss != NULL) {
		issuerIntName->setText(iss->getIntName());
		issuerIntName->setClickText(iss->getSqlItemId().toString());
		issuerIntName->setGreen();
		if (crl->verify(iss)) {
			signCheck->setText(crl->getSigAlg());
			signCheck->setGreen();
		} else {
			signCheck->setText(tr("Failed"));
			signCheck->setRed();
		}
		issuerSqlId = iss->getSqlItemId();
	} else {
		issuerIntName->setText(tr("Unknown signer"));
		issuerIntName->setDisabled(true);
		issuerIntName->disableToolTip();
		signCheck->setText(tr("Verification not possible"));
		signCheck->setDisabled(true);
	}

	connect(signCheck, SIGNAL(doubleClicked(QString)),
		MainWindow::getResolver(), SLOT(searchOid(QString)));
	connect(issuerIntName, SIGNAL(doubleClicked(QString)),
		this, SLOT(showIssuer()));

	descr->setText(crl->getIntName());
	lUpdate->setText(crl->getLastUpdate().toPretty());
	lUpdate->setToolTip(crl->getLastUpdate().toPrettyGMT());
	nUpdate->setText(crl->getNextUpdate().toPretty());
	nUpdate->setToolTip(crl->getNextUpdate().toPrettyGMT());
	version->setText((++crl->getVersion()));

	issuer->setX509name(crl->getSubject());

	RevocationList::setupRevocationView(certList, crl->getRevList(), iss);

	v3extensions->document()->setHtml(crl->printV3ext());

	comment->setPlainText(crl->getComment());
}

void CrlDetail::itemChanged(pki_base *pki)
{
	QVariant pkiSqlId = pki->getSqlItemId();

	if (pkiSqlId == issuerSqlId)
		issuerIntName->setText(pki->getIntName());
	if (pkiSqlId == crlSqlId)
		descr->setText(pki->getIntName());
}

void CrlDetail::showIssuer()
{
	CertDetail::showCert(this, Store.lookupPki<pki_x509>(issuerSqlId));
}

void CrlDetail::showCrl(QWidget *parent, pki_crl *crl)
{
	if (!crl)
		return;
	CrlDetail *dlg = new CrlDetail(parent);
	dlg->setCrl(crl);
	dlg->exec();
	delete dlg;
}
