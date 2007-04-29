/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "CertDetail.h"
#include "MainWindow.h"
#include "distname.h"
#include "clicklabel.h"
#include <qlabel.h>
#include <qpushbutton.h>
#include <qlineedit.h>

CertDetail::CertDetail(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::certImg);
	descr->setReadOnly(true);
}

void CertDetail::setCert(pki_x509 *cert)
{
	descr->setText(cert->getIntName());

	// examine the key
	pki_key *key= cert->getRefKey();
	if (key && key->isPrivKey()) {
		privKey->setText(key->getIntName());
		privKey->setGreen();
	}
	else {
		privKey->setText(tr("Not available"));
		privKey->setDisabled(true);
	}

	// examine the signature
	if ( cert->getSigner() == NULL) {
		signCert->setText(tr("Signer unknown"));
		signCert->setDisabled(true);
		signCert->disableToolTip();
	}
	else if ( cert == cert->getSigner())  {
		signCert->setText(tr("Self signed"));
		signCert->setGreen();
		signCert->disableToolTip();
	}

	else {
		signCert->setText(cert->getSigner()->getIntName());
		signCert->setGreen();
	}

	// check trust state
	trustState->disableToolTip();
	if (cert->getEffTrust() == 0) {
		trustState->setText(tr("Not trusted"));
		trustState->setRed();
	}
	else {
		trustState->setText(tr("Trusted"));
		trustState->setGreen();
	}

	// the serial
	serialNr->setText(cert->getSerial().toHex());

	// details of subject and issuer
	subject->setX509name(cert->getSubject());
	issuer->setX509name(cert->getIssuer());

	// The dates
	notBefore->setText(cert->getNotBefore().toPretty());
	notAfter->setText(cert->getNotAfter().toPretty());

	// validation of the Date
	dateValid->disableToolTip();
	if (cert->isRevoked()) {
		dateValid->setText(tr("Revoked: ") +
		cert->getRevoked().toPretty());
		dateValid->setRed();
	}
	else if (cert->checkDate() != 0) {
		dateValid->setText(tr("Not valid"));
		dateValid->setRed();
	}
	else {
		dateValid->setGreen();
		dateValid->setText(tr("Valid"));
	}
	// the fingerprints
	fpMD5->setText(cert->fingerprint(EVP_md5()));
	fpSHA1->setText(cert->fingerprint(EVP_sha1()));

	// V3 extensions
	v3extensions->document()->setHtml(cert->printV3ext());

	// Algorithm
	sigAlgo->setText(cert->getSigAlg());
}
