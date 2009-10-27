/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "KeyDetail.h"
#include "MainWindow.h"
#include "lib/pki_evp.h"
#include "widgets/distname.h"
#include "widgets/clicklabel.h"
#include <qlabel.h>
#include <qpushbutton.h>
#include <qlineedit.h>

KeyDetail::KeyDetail(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::keyImg);
	keyDesc->setReadOnly(true);
}

static QString CurveComment(int nid)
{
	for (size_t i=0; i<pki_evp::num_curves; i++) {
		if (pki_evp::curves[i].nid == nid)
			return QString(pki_evp::curves[i].comment);
	}
	return QString();
}

void KeyDetail::setKey(pki_evp *key)
{
	int nid;

	keyDesc->setText(key->getIntName());
	keyLength->setText(key->length());

	keyPrivEx->disableToolTip();
	if (key->isPubKey()) {
		keyPrivEx->setText(tr("Not available"));
		keyPrivEx->setRed();
	}
	else {
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
			tlHeader->setText(tr("Details of the DSA key"));
			tlPrivEx->setText(tr("Private key"));
			keyPubEx->setText(key->subprime());
			keyModulus->setText(key->pubkey());
			break;
		case EVP_PKEY_EC:
			nid = key->ecParamNid();
			tlHeader->setText(tr("Details of the EC key"));
			tlModulus->setText(tr("Public key"));
			tlPrivEx->setText(tr("Private key"));
			tlPubEx->setText(tr("Curve name"));
			keyPubEx->setText(OBJ_nid2sn(nid));
			keyPubEx->setToolTip(CurveComment(nid));
			keyModulus->setText(key->ecPubKey());
			break;
		default:
			tlHeader->setText(tr("UNKNOWN Key"));
	}
}
