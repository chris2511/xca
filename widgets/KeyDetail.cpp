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

void KeyDetail::setKey(pki_evp *key)
{
	keyDesc->setText( key->getIntName() );
	keyLength->setText( key->length() );

	keyPrivEx->disableToolTip();
	if (key->isPubKey()) {
		keyPrivEx->setText(tr("Not available") );
		keyPrivEx->setRed();
	}
	else {
		keyPrivEx->setText(tr("Available") );
		keyPrivEx->setGreen();
	}
	switch (key->getType()) {
		case EVP_PKEY_RSA:
			keyPubEx->setText( key->pubEx() );
			keyModulus->setText( key->modulus());
			break;
		case EVP_PKEY_DSA:
			tlPubEx->setText(tr("Sub prime"));
			tlModulus->setText(tr("Public key"));
			tlHeader->setText(tr("Details of the DSA key"));
			tlPrivEx->setText(tr("Private key"));
			keyPubEx->setText( key->subprime() );
			keyModulus->setText( key->pubkey());
			break;
		default:
			tlHeader->setText(tr("UNKNOWN Key"));
	}
}
