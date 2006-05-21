/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 *	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
 *
 *	http://www.trolltech.com
 *
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */


#include "KeyDetail.h"
#include "MainWindow.h"
#include "lib/pki_key.h"
#include "widgets/distname.h"
#include "widgets/clicklabel.h"
#include <Qt/qlabel.h>
#include <Qt/qpushbutton.h>
#include <Qt/qlineedit.h>

KeyDetail::KeyDetail(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::keyImg);
	keyDesc->setReadOnly(true);
}

void KeyDetail::setKey(pki_key *key)
{
	keyDesc->setText( key->getIntName() );
	keyLength->setText( key->length() );
	if (key->isPubKey()) {
		keyPrivEx->setText(tr("Not available") );
		keyPrivEx->setDisabled(true);
	}
	else {
		keyPrivEx->setText(tr("Available") );
		keyPrivEx->setDisabled(false);
	}
	switch (key->getType()) {
		case EVP_PKEY_RSA:
			keyPubEx->setText( key->pubEx() );
			keyModulus->setText( key->modulus());
			break;
		case EVP_PKEY_DSA:
			tlPubEx->setText("Sub prime");
			tlModulus->setText("Public key");
			tlHeader->setText("Details of the DSA key");
			tlPrivEx->setText("Private key");
			keyPubEx->setText( key->subprime() );
			keyModulus->setText( key->pubkey());
			break;
		default:
			tlHeader->setText("UNKNOWN Key");
	}
}
