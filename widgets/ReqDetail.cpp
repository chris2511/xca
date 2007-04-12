/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "ReqDetail.h"
#include "MainWindow.h"
#include "distname.h"
#include "clicklabel.h"
#include "lib/pki_x509req.h"
#include <qlabel.h>
#include <qlineedit.h>

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

