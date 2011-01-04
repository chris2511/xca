/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "KeyDetail.h"
#include "MainWindow.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "widgets/distname.h"
#include "widgets/clicklabel.h"
#include <QtGui/QLabel>
#include <QtGui/QPushButton>
#include <QtGui/QLineEdit>

KeyDetail::KeyDetail(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::keyImg);
	keyDesc->setReadOnly(true);
}

#ifndef OPENSSL_NO_EC
static QString CurveComment(int nid)
{
	for (size_t i=0; i<pki_evp::num_curves; i++) {
		if (pki_evp::curves[i].nid == nid)
			return QString(pki_evp::curves[i].comment);
	}
	return QString();
}
#endif

void KeyDetail::setKey(pki_key *key)
{
	keyDesc->setText(key->getIntName());
	keyLength->setText(key->length());

	keyPrivEx->disableToolTip();
	if (!key->isToken())
		cardBox->hide();
	tlHeader->setText(tr("Details of the %1 key").arg(key->getTypeString()));

	if (key->isPubKey()) {
		keyPrivEx->setText(tr("Not available"));
		keyPrivEx->setRed();
	} else if (key->isToken()) {
		image->setPixmap(*MainWindow::scardImg);
		pki_scard *card = (pki_scard *)key;
		cardBox->setTitle(tr("Token") +" [" +card->getCardLabel() +"]");
		cardManufacturer->setText(card->getManufacturer() + " " +
					card->getModel());
		cardSerial->setText(card->getSerial());
		keyPrivEx->setText(tr("Security token ID:%1").arg(card->getId()));
		keyBox->setTitle(tr("Key") + " [" + card->getLabel() + "]");
	} else {
		keyPrivEx->setText(tr("Available"));
		keyPrivEx->setGreen();
	}
	switch (key->getKeyType()) {
		case EVP_PKEY_RSA:
			keyPubEx->setText(key->pubEx());
			keyModulus->setText(key->modulus());
			break;
		case EVP_PKEY_DSA:
			tlPubEx->setText(tr("Sub prime"));
			tlModulus->setText(tr("Public key"));
			tlPrivEx->setText(tr("Private key"));
			keyPubEx->setText(key->subprime());
			keyModulus->setText(key->pubkey());
			break;
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
			int nid;
			nid = key->ecParamNid();
			tlModulus->setText(tr("Public key"));
			tlPrivEx->setText(tr("Private key"));
			tlPubEx->setText(tr("Curve name"));
			keyPubEx->setText(OBJ_nid2sn(nid));
			keyPubEx->setToolTip(CurveComment(nid));
			keyModulus->setText(key->ecPubKey());
			break;
#endif
		default:
			tlHeader->setText(tr("Unknown key"));
	}
}
