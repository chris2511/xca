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


#include "NewX509.h"
#include <qgroupbox.h>
#include <qcheckbox.h>
#include <qcombobox.h>
#include <qradiobutton.h>
#include <qlineedit.h>
#include <qlabel.h>
#include <qwhatsthis.h>
#include <qlistbox.h>
#include <qpixmap.h>
#include <qpushbutton.h>
#include <qvalidator.h>
#include <qbuttongroup.h>
#include "MainWindow.h"
#include "lib/x509name.h"

NewX509::NewX509(QWidget *parent , const char *name, db_key *key, db_x509req *req, db_x509 *cert, db_temp *temp, QPixmap *image, QPixmap *ns)
	:NewX509_UI(parent, name, true, 0)
{
	connect( this, SIGNAL(genKey()), parent, SLOT(newKey()) );
	connect( parent, SIGNAL(keyDone(QString)), this, SLOT(newKeyDone(QString)) );
	setCaption(tr(XCA_TITLE));
	keys = key;
	reqs = req;
	temps = temp;
	certs = cert;
	fixtemp = NULL;
	if (image) {
		bigImg1->setPixmap(*image);
		bigImg2->setPixmap(*image);
		bigImg3->setPixmap(*image);
		bigImg4->setPixmap(*image);
		bigImg5->setPixmap(*image);
		bigImg6->setPixmap(*image);
		nsImg->setPixmap(*ns);
	}
#ifdef qt3
	// pretty fat Title :-)
	QFont tFont;// = getFont();
	tFont.setPointSize(14);
	tFont.setBold(true);
	tFont.setUnderline(true);
	setTitleFont( tFont );
#else
	//setFont( tFont );
#endif	
	serialNr->setValidator( new QIntValidator(0, 32767, this));
	QStringList strings;
	// are there any useable private keys  ?
	if (keys) {
		strings = keys->get0PrivateDesc();
		keyList->insertStringList(strings);
	}
	else {
		keyList->setEnabled(false);
		genKeyBUT->setEnabled(false);
	}
	
	// any PKCS#10 requests to be used ?
	if (reqs) {
		strings = reqs->getDesc();
		if (strings.isEmpty()) {
			fromReqCB->setDisabled(true);
		}
		else {
			reqList->insertStringList(strings);
		}
	}
	else {
		reqList->setEnabled(false);
		fromReqCB->setEnabled(false);
	}
	
	// How about signing certificates ?
	if (certs) {
		strings = certs->getSignerDesc();
		if (strings.isEmpty()) {
			foreignSignRB->setDisabled(true);
			certList->setDisabled(true);
		}
		else {
			certList->insertStringList(strings);
		}
	}
	else {
		foreignSignRB->setDisabled(true);
		certList->setDisabled(true);
	}
	
	// settings for the templates ....
	if (temps) {
		strings = temps->getDesc();
		strings.prepend(tr("Server Template"));
		strings.prepend(tr("Client Template"));
		strings.prepend(tr("CA Template"));
		strings.prepend(tr("Empty Template"));
		tempList->insertStringList(strings);
	}
	else {
		templateBox->setEnabled(false);
	}		
	
	setFinishEnabled(page7,true);
	setNextEnabled(page2,false);
	signerChanged();
}
void NewX509::setRequest()
{
	setAppropriate(page4, false);
	setAppropriate(page5, false);
	setAppropriate(page6, false);
	finishButton()->setEnabled(true);
	changeDefault->setEnabled(false);
	changeDefault->setChecked(false);
	signerBox->setEnabled(false);
	startText=tr("\
Welcome to the settings for certificate signing requests.
A signing request needs a private key, so it will be created \
if there isn't any unused key available in the key database. \
This signing request can then be given to a Certification authority \
while the private key of the request and of the resulting certificate \
returned from the CA does never leave your computer.");
	endText=tr("\
You are done with entering all parameters for generating a Certificate signing \
request. The resulting request should be exported and send to an appropriate CA \
for signing it.");
	tText=tr("Certificate request");
	setup();
}

NewX509::~NewX509()
{

}

void NewX509::setTemp(pki_temp *temp)
{
	setAppropriate(page1, false);
	finishButton()->setEnabled(true);
	startText=tr("\
Welcome to the settings for Templates.
This templates do not refer to any ASN.1 structure but are used to keep default \
settings for signing requests and certificates. \
When creating a Request or Certificate the template can preset the needed fields \
with default settings.");
	endText=tr("\
You are done with entering all parameters for the Template.
After this step the template can be assigned to one of your CAs to be autoatically \
applied when signing with this CA.");
	tText=tr("Template");
	if (temp->getDescription() != "--") {
		description->setText(temp->getDescription().c_str());
		tText += tr(" change");
	}
	setup();
	
}
	
void NewX509::setCert()
{
	finishButton()->setEnabled(true);
	startText=tr("Welcome to the settings for Certificates. The information for the new Certificate can either be grabbed from a given Certificate-request or be filled in by hand. In the case of not signing a request there needs to be at least one unused key. If this is not the case it will be created. If you want to self-sign a request (unusual but nevertheless possible) you need the private key used to create the request.");
	endText=tr("You are done with entering all parameters for creating a Certificate.");
	tText=tr("Certificate");
	setup();
}

void NewX509::setup()
{
	startLabel->setText(startText);
	endLabel->setText(endText);
	setTitle(page0, tText + " Wizard");
	setTitle(page1, tText + " template selection");
	setTitle(page2, tText + " personal settings");
	setTitle(page4, tText + " X.509 v3 Extensions");
	setTitle(page5, tText + " key usage setup");
	setTitle(page6, tText + " Netscape extensions");
	setTitle(page7, tText + " Wizard finished");
}
	
void NewX509::defineTemplate(pki_temp *temp)
{
	fromTemplate(temp);
	templateChanged(temp);
	tempList->setEnabled(false);
}

void NewX509::defineRequest(pki_x509req *req)
{
	if (!req) return;
	fromReqCB->setEnabled(true);
	fromReqCB->setChecked(true);
	QString reqname = req->getDescription().c_str(); 
#ifdef qt3
	reqList->setCurrentText(reqname);
#else
	for (int i=0; i<reqList->count(); i++) {
		if (reqList->text(i) == reqname) {
			reqList->setCurrentItem(i);
			break;
		}
	}
#endif

}

void NewX509::defineCert(pki_x509 *defcert)
{
	// suggested from:  Andrey Brindeew <abr@abr.pp.ru>
	if (defcert && defcert->canSign()) {
		QString name = defcert->getIntName();
#ifdef qt3
		certList->setCurrentText(name);
#else
		for (int i=0; i<certList->count();i++) {
			if (certList->text(i) == name) {
				certList->setCurrentItem(i);
				break;
			}
		}
#endif
		foreignSignRB->setChecked(true);
		// certList->setEnabled(true);
	}
}	


int NewX509::lb2int(QListBox *lb)
{
	int x=0;
	for (int i=0; lb->item(i); i++) {
		if (lb->isSelected(i)){
			x |= 1<<i;
		}
	}
	return x;
}	


void NewX509::int2lb(QListBox *lb, int x)
{
	for (int i=0; lb->item(i); i++) {
		lb->setSelected(i, (1<<i) & x);
	}
}	


void NewX509::fromTemplate(pki_temp *temp)
{
	countryName->setText(temp->C.c_str());
	stateOrProvinceName->setText(temp->P.c_str());
	localityName->setText(temp->L.c_str());
	organisationName->setText(temp->O.c_str());
	organisationalUnitName->setText(temp->OU.c_str());
	commonName->setText(temp->CN.c_str());
	emailAddress->setText(temp->EMAIL.c_str());
	subAltName->setText(temp->subAltName.c_str());
	issAltName->setText(temp->issAltName.c_str());
	crlDist->setText(temp->crlDist.c_str());
	nsComment->setText(temp->nsComment.c_str());
	nsBaseUrl->setText(temp->nsBaseUrl.c_str());
	nsRevocationUrl->setText(temp->nsRevocationUrl.c_str());
	nsCARevocationUrl->setText(temp->nsCARevocationUrl.c_str());
	nsRenewalUrl->setText(temp->nsRenewalUrl.c_str());
	nsCaPolicyUrl->setText(temp->nsCaPolicyUrl.c_str());
	nsSslServerName->setText(temp->nsSslServerName.c_str());
	int2lb(nsCertType, temp->nsCertType);
	basicCA->setCurrentItem(temp->ca?1:0);
	bcCritical->setChecked(temp->bcCrit);
	kuCritical->setChecked(temp->keyUseCrit);
	ekuCritical->setChecked(temp->eKeyUseCrit);
	subKey->setChecked(temp->subKey);
	authKey->setChecked(temp->authKey);
	subAltCp->setChecked(temp->subAltCp);
	issAltCp->setChecked(temp->issAltCp);
	int2lb(keyUsage, temp->keyUse);
	int2lb(ekeyUsage, temp->eKeyUse);
	validNumber->setText(QString::number(temp->validN));
	validRange->setCurrentItem(temp->validM);
	if (temp->pathLen) {
		basicPath->setText(QString::number(temp->pathLen));
	}
	
}

void NewX509::toTemplate(pki_temp *temp)
{
	temp->setDescription(description->text().latin1());
	temp->C = countryName->text().latin1();
	temp->P = stateOrProvinceName->text().latin1();
	temp->L = localityName->text().latin1();
	temp->O = organisationName->text().latin1();
	temp->OU = organisationalUnitName->text().latin1();
	temp->CN = commonName->text().latin1();
	temp->EMAIL = emailAddress->text().latin1();
	temp->subAltName = subAltName->text().latin1();
	temp->issAltName = issAltName->text().latin1();
	temp->crlDist = crlDist->text().latin1();
	temp->nsComment = nsComment->text().latin1();
	temp->nsBaseUrl = nsBaseUrl->text().latin1();
	temp->nsRevocationUrl = nsRevocationUrl->text().latin1();
	temp->nsCARevocationUrl = nsCARevocationUrl->text().latin1();
	temp->nsRenewalUrl = nsRenewalUrl->text().latin1();
	temp->nsCaPolicyUrl = nsCaPolicyUrl->text().latin1();
	temp->nsSslServerName = nsSslServerName->text().latin1();
	temp->nsCertType =  lb2int(nsCertType);
	temp->ca = basicCA->currentItem();
	temp->bcCrit = bcCritical->isChecked();
	temp->keyUseCrit = kuCritical->isChecked();
	temp->eKeyUseCrit = ekuCritical->isChecked();
	temp->subKey = subKey->isChecked();
	temp->authKey = authKey->isChecked();
	temp->subAltCp = subAltCp->isChecked();
	temp->issAltCp = issAltCp->isChecked();
	temp->keyUse = lb2int(keyUsage);
	temp->eKeyUse = lb2int(ekeyUsage);
	temp->validN = validNumber->text().toInt();
	temp->validM = validRange->currentItem();
	temp->pathLen = basicPath->text().toInt();
}

void NewX509::toggleFromRequest()
{
	if (fromReqCB->isChecked()) {
		setAppropriate(page2, false);
		reqList->setEnabled(true);
	}
	else {
		setAppropriate(page2, true);
		reqList->setEnabled(false);
	}
}
	
	
void NewX509::dataChangeP2()
{
	CERR( "Data changed" );
	if (description->text() != ""  && countryName->text().length() !=1 &&
	    (keyList->count() > 0  || !keyList->isEnabled())){
		setNextEnabled(page2,true);
	}
	else {
		setNextEnabled(page2,false);
	}
}

void NewX509::showPage(QWidget *page)
{
	
	if (page == page0) {
		signerChanged();
		switchExtended();
		toggleFromRequest();
	}
	else if ( page == page2 ) {
		if (keyList->isEnabled() && keyList->count() == 0 ) {
			newKey();
		}
		dataChangeP2();
	}
	
	QWizard::showPage(page);
	
	if ( page == page2 ) {
		description->setFocus();	
	}
	else if (page == page4) {
		basicCA->setFocus();
	}

}

void NewX509::signerChanged()
{
	CERR("signer Changed");
	if (!certs) return;
	QString name = certList->currentText();
	CERR( "Certificate: " << name.latin1());
	
	if (name.isEmpty()) return;
	pki_x509 *cert = (pki_x509 *)certs->getByName(name);
	
	if (!cert) return;
	QString templ = cert->getTemplate().c_str();	
	
	if (templ.isEmpty()) return;
	CERR( "set Template: " << templ );
	
	templateChanged(templ);
	
}


void NewX509::templateChanged(QString tempname)
{
	if (!tempList->isEnabled()) return;
#ifdef qt3
	tempList->setCurrentText(tempname);
#else
	for (int i=0; i<tempList->count();i++) {
		if (tempList->text(i) == tempname) {
			tempList->setCurrentItem(i);
			break;
		}
	}
#endif
}


void NewX509::templateChanged(pki_temp *templ)
{
	QString tempname = templ->getDescription().c_str();
	templateChanged(tempname);
}

	
void NewX509::templateChanged()
{
	pki_temp *temp = NULL;
	int item;
	if (!appropriate(page1)) return;
	if (!tempList->isEnabled()) return;
	if ((item = tempList->currentItem())<4) {
		temp = new pki_temp("temp",item);
		if (temp) { 
			fromTemplate(temp);
			CERR("using default template: "<< item);
			delete (temp);
		}
		return;
	}
	QString name = tempList->currentText();
	if (name == "" || !temps) return;
	temp = (pki_temp *)temps->getByName(name);
	if (!temp) return;
	CERR("CHANGING TEMPLATE");
	fromTemplate(temp);
}

void NewX509::switchExtended()
{
	if ( !appropriate(page1) ) return;
	CERR( "SWITCH Extended");
	if (changeDefault->isChecked() || !templateBox->isEnabled()) {
		setAppropriate(page4, true);
		setAppropriate(page5, true);
		setAppropriate(page6, true);
	}
	else {
		setAppropriate(page4, false);
		setAppropriate(page5, false);
		setAppropriate(page6, false);
	}
}
		    
void NewX509::newKey()
{
	emit genKey();
}

void NewX509::newKeyDone(QString name)
{
	keyList->insertItem(name,0);
	keyList->setCurrentItem(0);
	dataChangeP2();	
}

void NewX509::helpClicked()
{
	QWhatsThis::enterWhatsThisMode();
}

pki_key *NewX509::getSelectedKey()
{
	return MainWindow::getKeyByName(keyList->currentText());
}

x509name NewX509::getX509name()
{
	x509name x;
	x.addEntryByNid(NID_commonName, commonName->text());
	x.addEntryByNid(NID_countryName, countryName->text());
	x.addEntryByNid(NID_localityName ,localityName->text());
	x.addEntryByNid(NID_stateOrProvinceName, stateOrProvinceName->text());
	x.addEntryByNid(NID_organizationName, organisationName->text());
	x.addEntryByNid(NID_organizationalUnitName, organisationalUnitName->text());
	x.addEntryByNid(NID_pkcs9_emailAddress, emailAddress->text());
	return x;
}
