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
	pki_x509 *possibleSigner; 
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
		if (strings.isEmpty()) {
			newKey();
		}
		else {
			keyList->insertStringList(strings);
		}
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
			// suggested from:  Andrey Brindeew <abr@abr.pp.ru>
			possibleSigner=(pki_x509 *)certs->getSelectedPKI();
			if (possibleSigner && possibleSigner->canSign()) {
				QString name = possibleSigner->getDescription().c_str();
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
	startText=tr("Welcome to the settings for Certificate signing requests.... (needs more prosa)");
	endText=tr("You are done with entering all parameters for generating a Certificate signing request..... (needs more prosa, volunteers ?)");
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
	startText=tr("Welcome to the settings for Templates.... (needs more prosa)");
	endText=tr("You are done with entering all parameters for generating a Template..... (needs more prosa, volunteers ?)");
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
	startText=tr("Welcome to the settings for Certificates.... (needs more prosa)");
	endText=tr("You are done with entering all parameters for generating a Certificate..... (needs more prosa, volunteers ?)");
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
	//setAppropriate(page1,false);
	//fixtemp = temp;
	fromTemplate(temp);
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
		dataChangeP2();
	}
	/*
	else if ( page == page4 ) { // disable Copy issuer alternative name 
		if (selfSignRB->isChecked()) { // for self signed certs
			issAltCp->setChecked(false);
			issAltCp->setEnabled(false);
		}
		else {
			issAltCp->setEnabled(true);
		}
	}
	*/
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
	// int i=0, sel=0;
	if (!certs) return;
	QString name = certList->currentText();
	CERR( "Certificate: " << name.latin1());
	if (name.isEmpty()) return;
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI(name.latin1());
	if (!cert) return;
	QString templ = cert->getTemplate().c_str();	
	if (templ.isEmpty()) return;
	CERR( "set Template: " << templ.latin1() );
#ifdef qt3
	tempList->setCurrentText(templ);
#else
	for (int i=0; i<tempList->count();i++) {
		if (tempList->text(i) == templ) {
			tempList->setCurrentItem(i);
			break;
		}
	}
#endif
	templateChanged();
	/*
	QStringList templates = tempList->list();
	for (i=0; i<templates.count(); i++) {
		if (templates[i] == templ) {
			sel = i;
		}
	}
	if (sel >0) {
		tempList->setSelected(sel);
	}*/
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
	temp = (pki_temp *)temps->getSelectedPKI(name.latin1());
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
