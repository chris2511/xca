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
#include <qlistview.h>
#include <qpixmap.h>
#include <qpushbutton.h>
#include <qvalidator.h>
#include <qbuttongroup.h>
#include "MainWindow.h"
#include "validity.h"
#include "lib/x509name.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"


int NewX509::eku_nid[EKUN_CNT] = {
  NID_server_auth,
  NID_client_auth,
  NID_code_sign,
  NID_email_protect,
  NID_time_stamp,
  NID_ms_code_ind,
  NID_ms_code_com,
  NID_ms_ctl_sign,
  NID_ms_sgc,
  NID_ms_efs,
  NID_ns_sgc,
  OBJ_create("1.3.6.1.4.1.311.10.3.4.1", "msEFSFR",
	"Microsoft EFS File Recovery" )
};

int NewX509::dn_nid[DISTNAME_CNT] = {
  NID_commonName,
  NID_surname,
  NID_serialNumber,
  NID_countryName,
  NID_localityName,
  NID_stateOrProvinceName,
  NID_organizationName,
  NID_organizationalUnitName,
  NID_title,
  NID_description,
  NID_name,
  NID_givenName,
  NID_initials,
  NID_dnQualifier,
  NID_role,
#if OPENSSL_VERSION_NUMBER >= 0x00907000L  
  NID_generationQualifier,
  NID_x500UniqueIdentifier,
  NID_pseudonym
#else
  OBJ_create("2.5.4.44", "generationQualifier", "generationQualifier"),
  OBJ_create("2.5.4.45", "x500UniqueIdentifier", "x500UniqueIdentifier"),
  OBJ_create("2.5.4.65", "pseudonym", "pseudonym")
#endif
};

NewX509::NewX509(QWidget *parent , const char *name, bool modal, WFlags f)
	:NewX509_UI(parent, name, modal, f)
{
        connect( extDNadd, SIGNAL(clicked()), this, SLOT(addX509NameEntry()) );
        connect( extDNdel, SIGNAL(clicked()), this, SLOT(delX509NameEntry()) );
		
	setCaption(tr(XCA_TITLE));
	fixtemp = NULL;
	nsImg->setPixmap(*MainWindow::nsImg);
#ifndef qt3
	// pretty fat Title :-)
	QFont tFont;// = getFont();
	tFont.setPointSize(14);
	tFont.setBold(true);
	tFont.setUnderline(true);
	//setFont( tFont );
#else
	//setFont( tFont );
#endif	
	// serialNr->setValidator( new QIntValidator(0, 32767, this));
	QStringList strings;
	 
	// are there any useable private keys  ?
	strings = MainWindow::keys->get0PrivateDesc();
	keyList->insertStringList(strings);
	hashAlgo->setCurrentItem(1);
	
	// any PKCS#10 requests to be used ?
	strings = MainWindow::reqs->getDesc();
	if (strings.isEmpty()) {
		fromReqCB->setDisabled(true);
		reqList->setDisabled(true);
	}
	else {
		reqList->insertStringList(strings);
	}
	
	// How about signing certificates ?
	strings = MainWindow::certs->getSignerDesc();
	if (strings.isEmpty()) {
		foreignSignRB->setDisabled(true);
		certList->setDisabled(true);
	}
	else {
		certList->insertStringList(strings);
	}
	
	// set dates to now and now + 1 year
	a1time a;
	notBefore->setDate(a.now());
	notAfter->setDate(a.now(60*60*24*356));
	
	// settings for the templates ....
	strings = MainWindow::temps->getDesc();
	strings.prepend(tr("Server Template"));
	strings.prepend(tr("Client Template"));
	strings.prepend(tr("CA Template"));
	strings.prepend(tr("Empty Template"));
	tempList->insertStringList(strings);
	
	// setup Extended keyusage
	for (int i=0; i<EKUN_CNT; i++)
		ekeyUsage->insertItem(OBJ_nid2ln(eku_nid[i]));

	// setup Distinguished Name 
	for (int i=0; i<DISTNAME_CNT; i++)
		extDNobj->insertItem(OBJ_nid2ln(dn_nid[i]));
	// init the X509 v3 context
	X509V3_set_ctx(&ext_ctx, NULL , NULL, NULL, NULL, 0);
	X509V3_set_ctx_nodb((&ext_ctx));

	// last polish 
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
	requestBox->setEnabled(false);
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
	setImage(MainWindow::csrImg);
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
	if (temp->getIntName() != "--") {
		description->setText(temp->getIntName());
		tText += tr(" change");
	}
	setup();
	privKeyBox->setEnabled(false);
	setImage(MainWindow::tempImg);
	
}
	
void NewX509::setCert()
{
	finishButton()->setEnabled(true);
	startText=tr("Welcome to the settings for Certificates. The information for the new Certificate can either be grabbed from a given Certificate-request or be filled in by hand. In the case of not signing a request there needs to be at least one unused key. If this is not the case it will be created. If you want to self-sign a request (unusual but nevertheless possible) you need the private key used to create the request.");
	endText=tr("You are done with entering all parameters for creating a Certificate.");
	tText=tr("Certificate");
	setup();
	setImage(MainWindow::certImg);
}

void NewX509::setImage(QPixmap *image)
{
	bigImg1->setPixmap(*image);
	bigImg2->setPixmap(*image);
	bigImg3->setPixmap(*image);
	bigImg4->setPixmap(*image);
	bigImg5->setPixmap(*image);
	bigImg6->setPixmap(*image);
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
	QString reqname = req->getIntName(); 
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
	countryName->setText(temp->C);
	stateOrProvinceName->setText(temp->P);
	localityName->setText(temp->L);
	organisationName->setText(temp->O);
	organisationalUnitName->setText(temp->OU);
	commonName->setText(temp->CN);
	emailAddress->setText(temp->EMAIL);
	subAltName->setText(temp->subAltName);
	issAltName->setText(temp->issAltName);
	crlDist->setText(temp->crlDist);
	nsComment->setText(temp->nsComment);
	nsBaseUrl->setText(temp->nsBaseUrl);
	nsRevocationUrl->setText(temp->nsRevocationUrl);
	nsCARevocationUrl->setText(temp->nsCARevocationUrl);
	nsRenewalUrl->setText(temp->nsRenewalUrl);
	nsCaPolicyUrl->setText(temp->nsCaPolicyUrl);
	nsSslServerName->setText(temp->nsSslServerName);
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
	//validNumber->setText(QString::number(temp->validN));
	//validRange->setCurrentItem(temp->validM);
	if (temp->pathLen) {
		basicPath->setText(QString::number(temp->pathLen));
	}
	
}

void NewX509::toTemplate(pki_temp *temp)
{
	temp->setIntName(description->text());
	temp->C = countryName->text();
	temp->P = stateOrProvinceName->text();
	temp->L = localityName->text();
	temp->O = organisationName->text();
	temp->OU = organisationalUnitName->text();
	temp->CN = commonName->text();
	temp->EMAIL = emailAddress->text();
	temp->subAltName = subAltName->text();
	temp->issAltName = issAltName->text();
	temp->crlDist = crlDist->text();
	temp->nsComment = nsComment->text();
	temp->nsBaseUrl = nsBaseUrl->text();
	temp->nsRevocationUrl = nsRevocationUrl->text();
	temp->nsCARevocationUrl = nsCARevocationUrl->text();
	temp->nsRenewalUrl = nsRenewalUrl->text();
	temp->nsCaPolicyUrl = nsCaPolicyUrl->text();
	temp->nsSslServerName = nsSslServerName->text();
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
	//temp->validN = validNumber->text().toInt();
	//temp->validM = validRange->currentItem();
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
			emit genKey();
		}
		dataChangeP2();
	}
	
	QWizard::showPage(page);
	
	if ( page == page2 ) {
		description->setFocus();	
	}
	else if (page == page4) {
		basicCA->setFocus();
		if (emailAddress->text().isEmpty())
			subAltCp->setEnabled(false);
		else
			subAltCp->setEnabled(true);
	}

}

void NewX509::signerChanged()
{
	QString name = certList->currentText();
	a1time snb, sna;
	
	if (name.isEmpty()) return;
	pki_x509 *cert = (pki_x509 *)MainWindow::certs->getByName(name);
	
	if (!cert) return;
	if (getSelectedSigner()->hasSubAltName())
		issAltCp->setEnabled(true);
	else
		issAltCp->setEnabled(false);
	
	QString templ = cert->getTemplate();	
	snb = cert->getNotBefore();
	sna = cert->getNotAfter();
	if (snb > notBefore->getDate())
		notBefore->setDate(snb);
	if (sna < notAfter->getDate())
		notAfter->setDate(sna);
	
	if (templ.isEmpty()) return;
	
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
	QString tempname = templ->getIntName();
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
			delete (temp);
		}
		return;
	}
	QString name = tempList->currentText();
	if (name.isEmpty()) return;
	temp = (pki_temp *)MainWindow::temps->getByName(name);
	if (!temp) return;
	fromTemplate(temp);
}

void NewX509::switchExtended()
{
	if ( !appropriate(page1) ) return;
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
	return (pki_key *)MainWindow::keys->getByName(keyList->currentText());
}

pki_x509 *NewX509::getSelectedSigner()
{
	return (pki_x509 *)MainWindow::certs->getByName(certList->currentText());
}

pki_x509req *NewX509::getSelectedReq()
{
	return (pki_x509req *)MainWindow::reqs->getByName(reqList->currentText());
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
	QListViewItem *lvi = extDNlist->firstChild();
	while (lvi != NULL) {
		int nid;
		nid = OBJ_ln2nid(lvi->text(0).latin1());
		x.addEntryByNid(nid, lvi->text(1));
		lvi = lvi->nextSibling();
	}
	return x;
}

void NewX509::setX509name(const x509name &n)
{
	for ( int i=0; i< n.entryCount(); i++) {
		int nid = n.nid(i);
		QStringList sl = n.entryList(i);
		switch (nid) {
			case NID_commonName: 
				commonName->setText(sl[2]); 
				// n.delEntry(i);
				break;
				/*
			case NID_commonName: 
				commonName->setText(sl[2]); 
				delEntry(i);
				break;
			case NID_commonName: 
				commonName->setText(sl[2]); 
				delEntry(i);
				break;
			case NID_commonName: 
				commonName->setText(sl[2]); 
				delEntry(i);
				break;
			case NID_commonName: 
				commonName->setText(sl[2]); 
				delEntry(i);
				break;
			case NID_commonName: 
				commonName->setText(sl[2]); 
				delEntry(i);
				break;
			case NID_commonName: 
				commonName->setText(sl[2]); 
				delEntry(i);
				break;
				*/
					
		}
	}
}

void NewX509::addX509NameEntry()
{
	new QListViewItem(extDNlist, extDNobj->currentText(), extDNname->text());
}

void NewX509::delX509NameEntry()
{
	extDNlist->removeItem(extDNlist->currentItem());
}

const EVP_MD *NewX509::getHashAlgo()
{
	const EVP_MD *ha[] = {EVP_md2(), EVP_md5(), EVP_sha1()};
	return ha[hashAlgo->currentItem()];
}
