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
 * 	written by Eric Young (eay@cryptsoft.com)"
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


#include "CertDetail.h"
#include "MainWindow.h"
#include "distname.h"
#include "clicklabel.h"
#include <qlabel.h>
#include <qtextview.h>
#include <qpushbutton.h>
#include <qlineedit.h>

CertDetail::CertDetail(QWidget *parent, const char *name, bool modal, WFlags f)
	:CertDetail_UI(parent,name,true,0)
{
	setCaption(tr(XCA_TITLE));
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
	}
	else if ( cert == cert->getSigner())  {
		signCert->setText(tr("Self signed"));
		signCert->setGreen();
	}
	
	else {
		signCert->setText(cert->getSigner()->getIntName());
		signCert->setGreen();
	}
	
	// check trust state
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
	v3Extensions->setText(cert->printV3ext());
	 
	// Algorithm
	sigAlgo->setText(cert->getSigAlg());
	sigAlgo->setReadOnly(true);
}

void CertDetail::setImport()
{
	// rename the buttons in case of import 
	but_ok->setText(tr("Import"));
	but_cancel->setText(tr("Discard"));
}
	
