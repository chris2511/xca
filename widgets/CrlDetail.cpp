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


#include "CrlDetail.h"
#include "MainWindow.h"
#include "lib/pki_crl.h"
#include "widgets/distname.h"
#include "widgets/clicklabel.h"
#include <qlabel.h>
#include <qtextview.h>
#include <qlistview.h>

CrlDetail::CrlDetail(QWidget *parent, const char *name, bool modal, WFlags f)
	:CrlDetail_UI(parent, name, modal, f)
{
	setCaption(tr(XCA_TITLE));
	certList->clear();
	certList->addColumn(tr("Name"));
	certList->addColumn(tr("Serial"));
	certList->addColumn(tr("Revokation"));
	image->setPixmap(*MainWindow::revImg);		 
}

void CrlDetail::setCrl(pki_crl *crl)
{
	int numc, i;
	pki_x509 *iss, *rev;
	x509rev revit;
	QListViewItem *current;
	iss = MainWindow::certs->getBySubject(crl->getIssuerName());
        
	// page 1
	if (iss != NULL) {
		issuerIntName->setText(iss->getIntName());
		pki_key *key = iss->getPubKey();
		if (crl->verify(key)) {
			signCheck->setText(tr("Ok"));
                	signCheck->setDisabled(false);
	        }
		else {
			signCheck->setText(tr("Failed"));
                	signCheck->setDisabled(true);
		}	
		delete key;
	}
	else {
		issuerIntName->setText("Unknown signer");
		issuerIntName->setDisabled(true);
                signCheck->setText(tr("Failed"));
                signCheck->setDisabled(true);
	}

	descr->setText(crl->getIntName());
        lUpdate->setText(crl->getLastUpdate().toPretty());
        nUpdate->setText(crl->getNextUpdate().toPretty());
        version->setText(crl->getVersion().toHex());
	
	// page 2
	issuer->setX509name(crl->getIssuerName());
	
	// page 3
	numc = crl->numRev();
	for (i=0; i<numc; i++) {
		revit = crl->getRev(i);
                rev = MainWindow::certs->getByIssSerial(iss, revit.getSerial());
                if (rev != NULL) {
                        current = new QListViewItem(certList,
                                        rev->getIntName());
                }
                else {
                        current = new QListViewItem(certList,
					"Unknown certificate" );
                } 
		current->setPixmap(0, *pki_x509::icon[2]);
                current->setText(1, revit.getSerial().toHex()) ;
                current->setText(2, revit.getDate().toSortable());
        }

	// page 4
        v3Extensions->setText(crl->printV3ext());
}
