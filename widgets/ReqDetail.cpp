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
 *	http://www.trolltech.com
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */


#include "ReqDetail.h"
#include "MainWindow.h"
#include "distname.h"
#include "clicklabel.h"
#include "lib/pki_x509req.h"
#include <Qt/qlabel.h>
#include <Qt/qlineedit.h>

ReqDetail::ReqDetail(QWidget *parent)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));
	image->setPixmap(*MainWindow::csrImg);
	descr->setReadOnly(true);
}

void ReqDetail::setReq(pki_x509req *req)
{
	// internal name and verification
	descr->setText(req->getIntName());
	if (!req->verify() ) {
		verify->setRed();
		verify->setText("Failed");
	}
	else {
		verify->setGreen();
		if (req->isSpki()) {
			verify->setText("SPKAC");
		}
		else {
			verify->setText("PKCS#10");
		}
	}
	// look for the private key
	pki_key *key =req->getRefKey();
	if (key) {
		privKey->setText(key->getIntName());
		privKey->setGreen();
	}
	else {
		privKey->setText(tr("Not available"));
		privKey->setDisabled(true);
	}
	// the subject
	subject->setX509name(req->getSubject());

	// Algorithm
	sigAlgo->setText(req->getSigAlg());

	// The extensions
	extList el = req->getV3Ext();
	v3extensions->document()->setHtml(el.getHtml("<br>"));
}

