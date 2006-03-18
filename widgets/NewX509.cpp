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
 * 	written by Eric Young (eay@cryptsoft.com)"
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
#include <Qt/qcheckbox.h>
#include <Qt/qcombobox.h>
#include <Qt/qradiobutton.h>
#include <Qt/qmessagebox.h>
#include <Qt/qlineedit.h>
#include <Qt/qlabel.h>
#include <Qt/qpixmap.h>
#include <Qt/qpushbutton.h>
#include <Qt/qvalidator.h>
#include "MainWindow.h"
#include "v3ext.h"
#include "lib/x509name.h"
#include "lib/db_key.h"
#include "lib/db_x509req.h"
#include "lib/db_x509.h"
#include "lib/db_temp.h"
#include "lib/oid.h"
#include "lib/func.h"


int NewX509::name_nid[] = {
	NID_commonName,
	NID_countryName,
	NID_localityName,
	NID_stateOrProvinceName,
	NID_organizationName,
	NID_organizationalUnitName,
	NID_pkcs9_emailAddress
};
							 
NewX509::NewX509(QWidget *parent)
	:QDialog(parent)
{
	int i;
	eku_nid = *MainWindow::eku_nid;
	dn_nid = *MainWindow::dn_nid;
	aia_nid = *MainWindow::aia_nid;
	QStringList sl;

	setupUi(this);

	sl << "Type" << "Content";
	extDNlist->setColumnCount(2);
	extDNlist->setHorizontalHeaderLabels(sl);
	setWindowTitle(tr(XCA_TITLE));
	fixtemp = NULL;
	
	nsImg->setPixmap(*MainWindow::nsImg);
	//setFont( tFont );
	serialNr->setValidator( new QRegExpValidator(QRegExp("[0-9a-fA-F]*"), this));
	QStringList strings;
	 
	// are there any useable private keys  ?
	strings = MainWindow::keys->get0PrivateDesc();
	keyList->insertItems(0, strings);
	hashAlgo->setCurrentIndex(2);
	
	// any PKCS#10 requests to be used ?
	strings = MainWindow::reqs->getDesc();
	if (strings.isEmpty()) {
		fromReqCB->setDisabled(true);
		reqList->setDisabled(true);
	}
	else {
		reqList->insertItems(0, strings);
	}
	
	// How about signing certificates ?
	strings = MainWindow::certs->getSignerDesc();
	if (strings.isEmpty()) {
		foreignSignRB->setDisabled(true);
		certList->setDisabled(true);
	}
	else {
		certList->insertItems(0, strings);
	}
	
	// set dates to now and now + 1 year
	a1time a;
	notBefore->setDate(a.now());
	notAfter->setDate(a.now(60*60*24*365));
	
	// settings for the templates ....
#warning fix templates
	strings.clear();
	//strings = MainWindow::temps->getDesc();
	strings.prepend(tr("Server Template"));
	strings.prepend(tr("Client Template"));
	strings.prepend(tr("CA Template"));
	strings.prepend(tr("Empty Template"));
	tempList->insertItems(0, strings);
	
	// setup Extended keyusage
	for (i=0; i < eku_nid.count(); i++)
		ekeyUsage->insertItem(0, OBJ_nid2ln(eku_nid[i]));

	// setup Distinguished Name 
	for (i=0; i < dn_nid.count(); i++)
		extDNobj->insertItem(0, OBJ_nid2ln(dn_nid[i]));

	// setup Authority Info Access
	for (i=0; i < aia_nid.count(); i++)
		aiaOid->insertItem(0, OBJ_nid2ln(aia_nid[i]));

	// init the X509 v3 context
	X509V3_set_ctx(&ext_ctx, NULL , NULL, NULL, NULL, 0);
	X509V3_set_ctx_nodb((&ext_ctx));

	// setup the list of x509nameEntrys
	name_ptr[0] = commonName;
	name_ptr[1] = countryName;
	name_ptr[2] = localityName;
	name_ptr[3] = stateOrProvinceName;
	name_ptr[4] = organisationName;
	name_ptr[5] = organisationalUnitName;
	name_ptr[6] = emailAddress;

	// last polish 
	signerChanged();
	checkAuthKeyId();
}

void NewX509::setRequest()
{
	requestBox->setEnabled(false);
	signerBox->setEnabled(false);
	validityBox->setEnabled(false);
	rangeBox->setEnabled(false);
	tabWidget->setCurrentIndex(1);
	tText=tr("Certificate signing request");
	setImage(MainWindow::csrImg);
}

NewX509::~NewX509()
{

}

void NewX509::setTemp(pki_temp *temp)
{
	tText=tr("Template");
	if (temp->getIntName() != "--") {
		description->setText(temp->getIntName());
		tText += tr(" change");
	}
//	privKeyBox->setEnabled(false);
//	validitybox->setEnabled(false);
//	setImage(MainWindow::tempImg);
	
}
	
void NewX509::setCert()
{
	tText=tr("Certificate");
	setImage(MainWindow::certImg);
}

void NewX509::setImage(QPixmap *image)
{
	bigImg->setPixmap(*image);
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
	reqList->setCurrentIndex(reqList->findText(reqname));
}

void NewX509::defineSigner(pki_x509 *defcert)
{
	// suggested from:  Andrey Brindeew <abr@abr.pp.ru>
	if (defcert  && defcert->canSign() ) {
		QString name = defcert->getIntName();
		certList->findText(name);
		foreignSignRB->setChecked(true);
		certList->setEnabled(true);
	}
}	


int NewX509::lb2int(QListWidget *lb)
{
	int i, x=0, c=lb->count();
	QListWidgetItem *item;
	
	for (i=0; i<c; i++) {
		item = lb->item(i);
		if (lb->isItemSelected(item)){
			x |= 1<<i;
		}
	}
	return x;
}	


void NewX509::int2lb(QListWidget *lb, int x)
{
	int i, c=lb->count();
	QListWidgetItem *item;

	for (i=0; i<c; i++) {
		item = lb->item(i);
		lb->setItemSelected(item, (1<<i) & x);
	}
}	


void NewX509::fromTemplate(pki_temp *temp)
{
	setX509name(temp->xname);
	subAltName->setText(temp->subAltName);
	issAltName->setText(temp->issAltName);
	crlDist->setText(temp->crlDist);
	setAuthInfAcc_string(temp->authInfAcc);
	certPol->setText(temp->certPol);
	nsComment->setText(temp->nsComment);
	nsBaseUrl->setText(temp->nsBaseUrl);
	nsRevocationUrl->setText(temp->nsRevocationUrl);
	nsCARevocationUrl->setText(temp->nsCARevocationUrl);
	nsRenewalUrl->setText(temp->nsRenewalUrl);
	nsCaPolicyUrl->setText(temp->nsCaPolicyUrl);
	nsSslServerName->setText(temp->nsSslServerName);
#warning settings
	int2lb(nsCertType, temp->nsCertType);
	basicCA->setCurrentIndex(temp->ca);
	bcCritical->setChecked(temp->bcCrit);
	kuCritical->setChecked(temp->keyUseCrit);
	ekuCritical->setChecked(temp->eKeyUseCrit);
	subKey->setChecked(temp->subKey);
	authKey->setChecked(temp->authKey);
	//subAltCp->setCheckState(temp->subAltCp);
	//issAltCp->setChecked(temp->issAltCp);
	int2lb(keyUsage, temp->keyUse);
	int2lb(ekeyUsage, temp->eKeyUse);
	validNumber->setText(QString::number(temp->validN));
	validRange->setCurrentIndex(temp->validM);
	midnightCB->setChecked(temp->validMidn);
	if (temp->pathLen) {
		basicPath->setText(QString::number(temp->pathLen));
	}
	notBefore->setNow();
	on_applyTime_clicked();
}

void NewX509::toTemplate(pki_temp *temp)
{
	temp->setIntName(description->text());
	temp->xname = getX509name();
	temp->subAltName = subAltName->text();
	temp->issAltName = issAltName->text();
	temp->crlDist = crlDist->text();
	temp->authInfAcc = getAuthInfAcc_string();
	temp->certPol = certPol->text();
	temp->nsComment = nsComment->text();
	temp->nsBaseUrl = nsBaseUrl->text();
	temp->nsRevocationUrl = nsRevocationUrl->text();
	temp->nsCARevocationUrl = nsCARevocationUrl->text();
	temp->nsRenewalUrl = nsRenewalUrl->text();
	temp->nsCaPolicyUrl = nsCaPolicyUrl->text();
	temp->nsSslServerName = nsSslServerName->text();
	temp->nsCertType =  lb2int(nsCertType);
	temp->ca = basicCA->currentIndex();
	temp->bcCrit = bcCritical->isChecked();
	temp->keyUseCrit = kuCritical->isChecked();
	temp->eKeyUseCrit = ekuCritical->isChecked();
	temp->subKey = subKey->isChecked();
	temp->authKey = authKey->isChecked();
//	temp->subAltCp = subAltCp->isChecked();
//	temp->issAltCp = issAltCp->isChecked();
	temp->keyUse = lb2int(keyUsage);
	temp->eKeyUse = lb2int(ekeyUsage);
	temp->validN = validNumber->text().toInt();
	temp->validM = validRange->currentIndex();
	temp->pathLen = basicPath->text().toInt();
	temp->validMidn = midnightCB->isChecked();
}

void NewX509::toggleFromRequest()
{
	if (fromReqCB->isChecked()) {
		reqList->setEnabled(true);
	}
	else {
		reqList->setEnabled(false);
	}
}
	
	
void NewX509::on_keyList_highlighted(const QString &keyname)
{
	if ( keyname.right(5) == "(DSA)" )
		hashAlgo->setDisabled(true);
	else
		hashAlgo->setDisabled(false);
}

void NewX509::dataChangeP2()
{
	if (description->text() != ""  && countryName->text().length() !=1 &&
	    (keyList->count() > 0  || !keyList->isEnabled())){
	}
}
#if 0
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
	
	if (page == page7) {
		QString issn, subn;
		if (fromReqCB->isChecked()) {
			pki_x509req *req = getSelectedReq();
			if (req) {
				subn = req->getSubject().oneLine();
			}
		}
		else
			subn = getX509name().oneLine();
		
		pki_x509 *issuer = getSelectedSigner();
		if (issuer && foreignSignRB->isChecked())
			issn = issuer->getSubject().oneLine();
		else
			issn = subn;
		
		subn = "<p><b>Subject:</b> " + subn;
		issn = "<p><b>Issuer:</b> " + issn;
		if (!appropriate(page1)) issn = "";
		
		v3Extensions->setText( subn + issn + "<p>" + createRequestText() );
	}
	
	if (page == page4) {
		checkAuthKeyId();
	}
			
	Q3Wizard::showPage(page);
	
	if ( page == page2 ) {
		description->setFocus();	
	}
	else if (page == page4) {
		basicCA->setFocus();
	}


}
#endif

void NewX509::signerChanged()
{
	a1time snb, sna;
	pki_x509 *cert = getSelectedSigner();
	
	if (!cert) return;
	
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
#warning set current Item
	//tempList->setCurrentItem(0, tempname);
	templateChanged();
}


void NewX509::templateChanged(pki_temp *templ)
{
	QString tempname = templ->getIntName();
	templateChanged(tempname);
}

	
void NewX509::templateChanged()
{
#if 0
	pki_temp *temp = NULL;
	int item;
	if (!tempList->isEnabled()) return;
	if ((item = tempList->currentIndex())<4) {
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
#else
#warning templateChanged
#endif

}
#if 0
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
#endif
void NewX509::checkAuthKeyId()
{
	bool enabled = false;

	if (foreignSignRB->isChecked()) {
		if (getSelectedSigner()->hasSubAltName())
		enabled = true;
	}
	else { // Self signed
		if (subKey->isChecked() && subKey->isEnabled())
			enabled = true;
	}
	authKey->setEnabled(enabled);
}

void NewX509::on_foreignSignRB_clicked(){
	checkAuthKeyId();
}
void NewX509::on_subKey_clicked(){
	checkAuthKeyId();
}

void NewX509::newKeyDone(QString name)
{
	keyList->insertItem(0, name);
	keyList->setCurrentIndex(0);
	dataChangeP2();	
}

void NewX509::helpClicked()
{
	//Q3WhatsThis::enterWhatsThisMode();
}

pki_key *NewX509::getSelectedKey()
{
	QString name = pki_key::removeTypeFromIntName(keyList->currentText());
	return (pki_key *)MainWindow::keys->getByName(name);
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
	int j, row;
	
	for (j = 0; j<EXPLICIT_NAME_CNT; j++) {
		x.addEntryByNid(name_nid[j], name_ptr[j]->text());
	}

	row = extDNlist->rowCount();
	for (j=0; j<row; j++) {
		int nid;
		nid = OBJ_ln2nid(CCHAR(extDNlist->item(j,0)->text()));
		x.addEntryByNid(nid, CCHAR(extDNlist->item(j,1)->text()));
	}
	return x;
}

void NewX509::setX509name(const x509name &n)
{
	int j;	
	extDNlist->clear();
	for ( j = 0; j<EXPLICIT_NAME_CNT; j++) {
		name_ptr[j]->setText(""); 
	}
	for ( int i=0; i< n.entryCount(); i++) {
		int nid = n.nid(i);
		QStringList sl = n.entryList(i);
		for ( j = 0; j<EXPLICIT_NAME_CNT; j++) {
			if (nid == name_nid[j] && name_ptr[j]->text().isEmpty()) { 
				name_ptr[j]->setText(sl[2]); 
				break;
			}
		}
		if (j == EXPLICIT_NAME_CNT) {
			QTableWidgetItem *tw;
			int row;
			
			row = extDNlist->rowCount();
			extDNlist->setRowCount(row+1);
	
			for (int i=0; i<2; i++) {
				tw = new QTableWidgetItem(sl[i+1]);
				extDNlist->setItem(row, i, tw);
			}
		}
	}
}

void NewX509::on_extDNadd_clicked()
{
	QTableWidgetItem *tw;
	int row;
			
	row = extDNlist->rowCount();
	extDNlist->setRowCount(row+1);
	
	tw = new QTableWidgetItem(extDNobj->currentText());
	extDNlist->setItem(row, 0, tw);
	
	tw = new QTableWidgetItem(extDNname->text());
	extDNlist->setItem(row, 1, tw);
}

void NewX509::on_extDNdel_clicked()
{
	extDNlist->removeRow(extDNlist->currentRow());
}

const EVP_MD *NewX509::getHashAlgo()
{
	const EVP_MD *ha[] = {EVP_md2(), EVP_md5(), EVP_sha1()};
	return ha[hashAlgo->currentIndex()];
}

void NewX509::on_applyTime_clicked()
{
	applyTD(this, validNumber->text().toInt(), validRange->currentIndex(),
			midnightCB->isChecked(), notBefore, notAfter);
}

void NewX509::editV3ext(QLineEdit *le, QString types, int n)
{
	v3ext *dlg;
	pki_x509 *cert, *signcert;
	pki_x509req *req;
	
	// initially create cert 
	cert = new pki_x509();
	if (fromReqCB->isChecked()) {
		req = getSelectedReq();
		cert->setSubject(req->getSubject());
	} else {
		cert->setSubject(getX509name());
	}
	// Step 2 - select Signing
	if (foreignSignRB->isChecked()) {
		signcert = getSelectedSigner();
	} else {
		signcert = cert;
	}
	
	dlg = new v3ext(this);
	dlg->addInfo(le, types.split(',' ), n,
			signcert->getCert(), cert->getCert());
	dlg->exec();
	delete(dlg);
	delete(cert);
}

void NewX509::on_editSubAlt_clicked()
{
	editV3ext(subAltName, "email,email:copy,RID,URI,DNS,IP,otherName",
			NID_subject_alt_name);
}

void NewX509::on_editIssAlt_clicked()
{
	editV3ext(issAltName, "email,RID,URI,DNS,IP,issuer:copy,otherName",
			NID_issuer_alt_name);
}

void NewX509::on_editCrlDist_clicked()
{
	editV3ext(crlDist, "URI", NID_crl_distribution_points);
}

void NewX509::on_editAuthInfAcc_clicked()
{
	editV3ext(authInfAcc, "email,RID,URI,DNS,IP", NID_info_access);
}

