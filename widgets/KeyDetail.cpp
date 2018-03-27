/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "KeyDetail.h"
#include "MainWindow.h"
#include "lib/main.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "widgets/distname.h"
#include "widgets/clicklabel.h"
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>

KeyDetail::KeyDetail(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	image->setPixmap(*MainWindow::keyImg);
	keyModulus->setFont(XCA_application::tableFont);
	tabWidget->setCurrentIndex(0);
}

#ifndef OPENSSL_NO_EC
static QString CurveComment(int nid)
{
	foreach(builtin_curve curve, pki_key::builtinCurves) {
		if (curve.nid == nid)
			return curve.comment;
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
		tabWidget->removeTab(1);
	tlHeader->setText(tr("Details of the %1 key").arg(key->getTypeString()));
	comment->setPlainText(key->getComment());

	if (key->isPubKey()) {
		keyPrivEx->setText(tr("Not available"));
		keyPrivEx->setRed();
	} else if (key->isToken()) {
		image->setPixmap(*MainWindow::scardImg);
		pki_scard *card = static_cast<pki_scard *>(key);
		cardLabel->setText(card->getCardLabel());
		cardModel->setText(card->getModel());
		cardManufacturer->setText(card->getManufacturer());
		cardSerial->setText(card->getSerial());
		slotLabel->setText(card->getLabel());
		cardId->setText(card->getId());
		keyPrivEx->setText(tr("Security token"));
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
			tlModulus->setTitle(tr("Public key"));
			tlPrivEx->setText(tr("Private key"));
			keyPubEx->setText(key->subprime());
			keyModulus->setText(key->pubkey());
			break;
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
			int nid;
			nid = key->ecParamNid();
			tlModulus->setTitle(tr("Public key"));
			tlPrivEx->setText(tr("Private key"));
			tlPubEx->setText(tr("Curve name"));
			keyPubEx->setText(OBJ_nid2sn(nid));
			connect(keyPubEx, SIGNAL(doubleClicked(QString)),
				MainWindow::getResolver(),
				SLOT(searchOid(QString)));
			keyPubEx->setToolTip(CurveComment(nid));
			keyModulus->setText(key->ecPubKey());
			break;
#endif
		default:
			tlHeader->setText(tr("Unknown key"));
	}
}
