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


#include "CertView.h"
#include "MainWindow.h"
#include <qcheckbox.h>
#include <qlabel.h>
#include <qcombobox.h>
#include <qradiobutton.h>
#include <qmessagebox.h>
#include <qpopupmenu.h>
#include <qtextview.h>
#include <qpushbutton.h>
#include <qinputdialog.h>
#include "ui/CertExtend.h"
#include "ExportCert.h"
#include "ui/CertDetail.h"
#include "ui/TrustState.h"
#include "ExportTinyCA.h"
#include "validity.h"
#include "lib/pki_pkcs12.h"
#include "lib/pki_pkcs7.h"

#ifdef WIN32
#include <direct.h>     // to define mkdir function
#include <windows.h>    // to define mkdir function
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

CertView::CertView(QWidget * parent = 0, const char * name = 0, WFlags f = 0)
        :XcaListView(parent, name, f)
{
	certicon[0] = loadImg("validcert.png");
	certicon[1] = loadImg("validcertkey.png");
	certicon[2] = loadImg("invalidcert.png");
	certicon[3] = loadImg("invalidcertkey.png");
	addColumn(tr("Common Name"));
	addColumn(tr("Serial"));
	addColumn(tr("not After"));
	addColumn(tr("Trust state"));
	addColumn(tr("Revokation"));
	viewState=1; // Tree View
}	


void CertView::newItem()
{
	NewX509 *dlg = MainWindow::newX509(MainWindow::certImg);
	dlg->setCert();
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}


void CertView::newCert(NewX509 *dlg)
{
	pki_x509 *cert = NULL;
	pki_x509 *signcert = NULL;
	pki_x509req *req = NULL;
	pki_key *signkey = NULL, *clientkey = NULL, *tempkey = NULL;
	a1int serial;
	a1time notBefore, notAfter;
	x509name subject;
	int i;
	const QString critical = "critical";
	
	QStringList cont;
	
	QString ekeyusage[]= {"serverAuth","clientAuth","codeSigning","emailProtection",
		"timeStamping","msCodeInd","msCodeCom",
		"msCTLSign","msSGC","msEFS","nsSGC","1.3.6.1.4.1.311.10.3.4.1"};
	QString keyusage[] ={"digitalSignature", "nonRepudiation", "keyEncipherment",
		"dataEncipherment", "keyAgreement", "keyCertSign",
		"cRLSign", "encipherOnly", "decipherOnly"};
	QString certTypeList[] = { "client", "server", "email", "objsign",
		"sslCA", "emailCA", "objCA" };

	QListBoxItem *item;
	
	emit init_database();

    try {	
	// Step 1 - Subject and key
	if (!dlg->fromReqCB->isChecked()) {
	    clientkey = dlg->getSelectedKey();
	    subject = dlg->getX509name();
	}
	else {
	    // A PKCS#10 Request was selected 
	    req = (pki_x509req *)MainWindow::reqs->getByName(dlg->reqList->currentText());
	    if (Error(req)) return;
	    clientkey = req->getRefKey();
	    if (clientkey == NULL) {
		    clientkey = req->getPubKey();
		    tempkey = clientkey;
	    }
	    subject = req->getSubject();
	}
		
	// Step 2 - select Signing
	if (dlg->foreignSignRB->isChecked()) {
		signcert = (pki_x509 *)db->getByName(dlg->certList->currentText());
		serial = signcert->getIncCaSerial();
		signkey = signcert->getRefKey();
		// search for serial in database
		
	}
	else {
		signkey = clientkey;	
		bool ok;
		serial = dlg->serialNr->text().toInt(&ok);
		if (!ok) serial = 0;
	}
	
	
	// Step 3 - Choose the Date and all the V3 extensions
	
	// Date handling
	notBefore = dlg->validity->getNotBefore();
	notAfter = dlg->validity->getNotAfter();
	
	// initially create cert 
	cert = new pki_x509();
	if (!signcert) signcert=cert;	
	cert->setIntName(req->getIntName());
	cert->setPubKey(clientkey);
	cert->setSubject(subject);
	cert->setIssuer(signcert->getSubject());
	if (cert->resetTimes(signcert) > 0) {
		if (QMessageBox::information(this,tr(XCA_TITLE),
			tr("The validity times for the certificate need to get adjusted to not exceed those of the signer"),
			tr("Continue creation"), tr("Abort")
		))
			throw errorEx("");
	}
			
	// STEP 4
	// handle extensions
	
	// basic constraints
	if (dlg->bcCritical->isChecked()) cont << critical;
	cont << (QString)"CA:" + dlg->basicCA->currentText();
	cont << (QString)"pathlen:" + dlg->basicPath->text();
	cert->addV3ext(NID_basic_constraints, cont.join(", "));
	 
	// Subject Key identifier
	if (dlg->subKey->isChecked()) {
		cert->addV3ext(NID_subject_key_identifier, "hash");
	}
	
	// Authority Key identifier
	if (dlg->authKey->isChecked()) {
		cert->addV3ext(NID_authority_key_identifier,
			"keyid:always,issuer:always");
	}
	 
	// key usage
	cont.clear(); 
	if (dlg->kuCritical->isChecked()) cont << critical;
	for (i=0; (item = dlg->keyUsage->item(i)); i++) {	
		if (item->selected()){
			cont << keyusage[i];
		}
	}
	cert->addV3ext(NID_key_usage, cont.join(", "));
	
	// extended key usage
	cont.clear();
	if (dlg->ekuCritical->isChecked()) cont << critical;
	for (i=0; (item = dlg->ekeyUsage->item(i)); i++) {	
		if (item->selected()){
			cont << ekeyusage[i];
		}
	}
	cert->addV3ext(NID_ext_key_usage, cont.join(", "));
	
	
	// Subject Alternative name
	if (dlg->subAltCp->isChecked()) {
		if (subject.getEntryByNid(NID_pkcs9_emailAddress).length() == 0) {
			if (QMessageBox::information(this,tr(XCA_TITLE),
			   tr("You requested to copy the subject E-Mail address but it is empty !"),
			   tr("Continue creation"), tr("Abort")
			))
				throw errorEx("");	
		}
		else {
			cont << (QString)"email:copy";
		}
	}
	cont << dlg->subAltName->text();
	cert->addV3ext(NID_subject_alt_name, cont.join(", "));
	
	// issuer alternative name	
	cont.clear();
	if (dlg->issAltCp->isChecked()) {
		if (!signcert->hasSubAltName()) {
			if (QMessageBox::information(this,tr(XCA_TITLE),
			   tr("You requested to copy the issuer alternative name but it is empty !"),
			   tr("Continue creation"), tr("Abort")
			))
				throw errorEx("");	
		}
		else {
			cont << (QString)"issuer:copy";
		}
	}
	cont << dlg->issAltName->text();
	cert->addV3ext(NID_issuer_alt_name, cont.join(", "));

	// CRL distribution points
	if (!dlg->crlDist->text().isEmpty()) {
		CERR("CRL dist. Point: "<<  dlg->crlDist->text() );
		cert->addV3ext(NID_crl_distribution_points, dlg->crlDist->text());
	}
		
	// STEP 5
	// Nestcape extensions 
	cont.clear();
	for (i=0; (item = dlg->nsCertType->item(i)); i++) {	
		if (item->selected()){
			cont <<  certTypeList[i];
		}
	}
	cert->addV3ext(NID_netscape_cert_type, cont.join(", "));
	cert->addV3ext(NID_netscape_base_url, dlg->nsBaseUrl->text());
	cert->addV3ext(NID_netscape_revocation_url, dlg->nsRevocationUrl->text());
	cert->addV3ext(NID_netscape_ca_revocation_url, dlg->nsCARevocationUrl->text());
	cert->addV3ext(NID_netscape_renewal_url, dlg->nsRenewalUrl->text());
	cert->addV3ext(NID_netscape_ca_policy_url, dlg->nsCaPolicyUrl->text());
	cert->addV3ext(NID_netscape_ssl_server_name, dlg->nsSslServerName->text());
	cert->addV3ext(NID_netscape_comment, dlg->nsComment->text());
	
	// and finally sign the request 
	cert->sign(signkey);
	CERR( "SIGNED");
	insert(cert);
	CERR("inserted");
	if (tempkey != NULL) delete(tempkey);
	CERR("Dialog deleted" );
	updateView();
	return;
    }
    catch (errorEx &err) {
	Error(err);
	delete cert;
	if (tempkey != NULL) delete(tempkey);
    }
	
}

void CertView::extendCert()
{
	pki_x509 *oldcert = NULL, *signer = NULL, *newcert =NULL;
	pki_key *signkey = NULL;
	a1time time;
	a1int serial;
	emit init_database();
	try {
		CertExtend_UI *dlg = new CertExtend_UI(this, NULL, true);
		dlg->image->setPixmap(*MainWindow::certImg);
		dlg->validity->setNotBefore(time.now());
		dlg->validity->setNotAfter(time.now(60 * 60 * 24 * 356));
		
		if (!dlg->exec()) {
			delete dlg;
			return;
		}
		oldcert = (pki_x509 *)getSelected();
		if (!oldcert || !(signer = oldcert->getSigner()) || !(signkey = signer->getRefKey()) || signkey->isPubKey()) return;
		newcert = new pki_x509(oldcert);
		serial = signer->getIncCaSerial();
		
		// get signers own serial to avoid having the same
		if (serial == signer->getSerial()) {
			serial = signer->getIncCaSerial(); // just take the next one
		}
		db->updatePKI(signer);  // FIXME::not so pretty ....
		
		// change date and serial
		newcert->setSerial(serial);
		newcert->setNotBefore(dlg->validity->getNotBefore());
		newcert->setNotAfter(dlg->validity->getNotAfter());

		if (newcert->resetTimes(signer) > 0) {
			if (QMessageBox::information(this,tr(XCA_TITLE),
				tr("The validity times for the certificate need to get adjusted to not exceed those of the signer"),
				tr("Continue creation"), tr("Abort")
			))
				throw errorEx("");
		}
		
		
		// and finally sign the request 
		newcert->sign(signkey);
		CERR( "SIGNED");
		insert(newcert);
		CERR("inserted");
		delete dlg;
	}
	catch (errorEx &err) {
		Error(err);
		if (newcert)
			delete newcert;
	}
}
		
void CertView::showItem(pki_base *basecert, bool import)
{
	pki_x509 *cert = (pki_x509 *)basecert;
	if (!cert) return; 
	if (Error(cert)) return ;
    try {
	CertDetail_UI *dlg = new CertDetail_UI(this,0,true);
	bool ret;
	dlg->image->setPixmap(*MainWindow::certImg);
	dlg->descr->setText(cert->getIntName());
	dlg->setCaption(tr(XCA_TITLE));

	// examine the key
	pki_key *key= cert->getRefKey();
	if (key)
	     if (key->isPrivKey()) {
		dlg->privKey->setText(key->getIntName());
	      	dlg->privKey->setDisabled(false);
	     }								

	// examine the signature
	if ( cert->getSigner() == NULL) {
		dlg->verify->setText(tr("SIGNER UNKNOWN"));
	}
	else if ( cert->compare(cert->getSigner()) ) {
		dlg->verify->setText(tr("SELF SIGNED"));
	}
	
	else {
		dlg->verify->setText(cert->getSigner()->getIntName());
	}

	// check trust state
	if (cert->getEffTrust() == 0) {
	      	dlg->verify->setDisabled(true);
	}
	CERR( cert->getEffTrust() );
	
	// the serial
	dlg->serialNr->setText(cert->getSerial().toHex());	

	// details of subject
	x509name subj = cert->getSubject();
	QString land = subj.getEntryByNid(NID_countryName);
	QString land1 = subj.getEntryByNid(NID_stateOrProvinceName);
	if (land != "" && land1 != "")
		land += " / " +land1;
	else
		land+=land1;
	
	dlg->dnCN->setText(subj.getEntryByNid(NID_commonName));
	dlg->dnC->setText(land);
	dlg->dnL->setText(subj.getEntryByNid(NID_localityName));
	dlg->dnO->setText(subj.getEntryByNid(NID_organizationName));
	dlg->dnOU->setText(subj.getEntryByNid(NID_organizationalUnitName));
	dlg->dnEmail->setText(subj.getEntryByNid(NID_pkcs9_emailAddress));
	
	// same for issuer....	
	x509name iss = cert->getIssuer();
	land = iss.getEntryByNid(NID_countryName);
	land1 = iss.getEntryByNid(NID_stateOrProvinceName);
	if (land != "" && land1 != "")
		land += " / " +land1;
	else
		land+=land1;

	dlg->dnCN_2->setText(iss.getEntryByNid(NID_commonName) );
	dlg->dnC_2->setText(land);
	dlg->dnL_2->setText(iss.getEntryByNid(NID_localityName));
	dlg->dnO_2->setText(iss.getEntryByNid(NID_organizationName));
	dlg->dnOU_2->setText(iss.getEntryByNid(NID_organizationalUnitName));
	dlg->dnEmail_2->setText(iss.getEntryByNid(NID_pkcs9_emailAddress));
	dlg->notBefore->setText(cert->getNotBefore().toPretty());
	dlg->notAfter->setText(cert->getNotAfter().toPretty());
	MARK
	
	// validation of the Date
	if (cert->checkDate() == -1) {
		dlg->dateValid->setText(tr("Not valid"));
	      	dlg->dateValid->setDisabled(true);
	}
	if (cert->checkDate() == +1) {
		dlg->dateValid->setText(tr("Not valid"));
	      	dlg->dateValid->setDisabled(true);
	}
	if (cert->isRevoked()) {
		dlg->dateValid->setText(tr("Revoked: ") +
			cert->getRevoked().toPretty());
	      	dlg->dateValid->setDisabled(true);
		
	}
	// the fingerprints
	dlg->fpMD5->setText(cert->fingerprint(EVP_md5()));
	dlg->fpSHA1->setText(cert->fingerprint(EVP_sha1()));
	
	// V3 extensions
	dlg->v3Extensions->setText(cert->printV3ext());
	
	// rename the buttons in case of import 
	if (import) {
		dlg->but_ok->setText(tr("Import"));
		dlg->but_cancel->setText(tr("Discard"));
	}

	// show it to the user...	
	QString odesc = cert->getIntName();
	ret = dlg->exec();
	QString ndesc = dlg->descr->text();
	delete dlg;
	if (!ret && import) {
		delete cert;
	}
	if (!ret) return;	
	
	emit init_database();
	
	if (import) {
		cert = (pki_x509 *)insert(cert);
	}
	if (ndesc != odesc) {
		db->renamePKI(cert, ndesc);
		return;
	}
    }
    catch (errorEx &err) {
	    Error(err);
    }
    return ;
}

void CertView::deleteItem()
{
    try {
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	if (cert->getSigner() && cert->getSigner() != cert && cert->getSigner()->canSign()) {
		QMessageBox::information(this,tr(XCA_TITLE),
			tr("It is actually not a good idea to delete a cert that was signed by you") +":\n'" + 
			cert->getIntName() + "'\n" ,
			tr("Ok") );
	}
    	deleteItem_default(tr("The certificate"), tr("is going to be deleted"));
    }
    catch (errorEx &err) {
	    Error(err);
    }
}

void CertView::load()
{
	QStringList filter;
	filter.append(tr("Certificates ( *.pem *.der *.crt *.cer )")); 
	filter.append(tr("All files ( *.* )"));
	load_default(filter,tr("Certificate import"));
}

pki_base *CertView::loadItem(QString fname)
{
	pki_x509 *cert = new pki_x509(fname);
	return cert;
}

void CertView::loadPKCS12()
{
	pki_pkcs12 *pk12;
	QStringList filt;
	filt.append(tr("PKCS#12 Certificates ( *.p12 *.pfx )")); 
	filt.append(tr("All files ( *.* )"));
	QStringList slist;
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate import"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
        dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
	}
	delete dlg;
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		try {
			pk12 = new pki_pkcs12(s, &MainWindow::passRead);
			insertP12(pk12);
		}
		catch (errorEx &err) {
			Error(err);
		}
		delete pk12;
	}
}

			
void CertView::insertP12(pki_pkcs12 *pk12)
{
	pki_x509 *acert;
	pki_key *akey;

	try {
		akey = pk12->getKey();
		acert = pk12->getCert();
#ifdef INSERT_WO_ASK
		insertKey(akey);
		insertCert(acert);
		for (int i=0; i<pk12->numCa(); i++) {
			acert = pk12->getCa(i);
			insertCert(acert);
		}
#else
		// keyList->show(akey, true);
		showItem(acert,true);
		for (int i=0; i<pk12->numCa(); i++) {
			acert = pk12->getCa(i);
			showItem(acert, true);
		}
#endif			
		//if (keys)
			//FIXME:: keys->updateView();
	}
	catch (errorEx &err) {
		Error(err);
	}
	MARK
}	
	

void CertView::loadPKCS7()
{
	pki_pkcs7 *pk7 = NULL;
	pki_x509 *acert;
	QStringList filt;
	filt.append(tr("PKCS#7 data ( *.p7s *.p7m *.p7b )")); 
	filt.append(tr("All files ( *.* )"));
	QStringList slist;
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate import"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
        dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
	}
	delete dlg;
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		try {
			pk7 = new pki_pkcs7(s);
			pk7->readP7(s);
			for (int i=0; i<pk7->numCert(); i++) {
				acert = pk7->getCert(i);
				showItem(acert, true);
			}
			// keys->updateView();
		}
		catch (errorEx &err) {
			Error(err);
		}
		if (pk7) delete pk7;
	}
}


pki_base *CertView::insert(pki_base *item)
{
    pki_x509 *cert = (pki_x509 *)item;
    emit init_database();
    try {
	pki_x509 *oldcert = (pki_x509 *)db->getByReference(cert);
	if (oldcert) {
	   QMessageBox::information(this,tr(XCA_TITLE),
		tr("The certificate already exists in the database as") +":\n'" +
		oldcert->getIntName() + 
		"'\n" + tr("and so it was not imported"), "OK");
	   delete(cert);
	   return oldcert;
	}
	CERR( "insertCert: inserting" );
	insert(cert);
    }
    catch (errorEx &err) {
	    Error(err);
    }
    a1int serial;
    // check the CA serial of the CA of this cert to avoid serial doubles
    if (cert->getSigner() != cert && cert->getSigner()) {
	serial = cert->getSerial();
	CERR("OTHER SIGNER" << serial.getLong());
    	if (cert->getSigner()->getCaSerial() <serial ) {
	    QMessageBox::information(this,tr(XCA_TITLE),
		tr("The certificate-serial is higher than the next serial of the signer it will be set to ") +
		QString::number((++serial).getLong()), "OK");
	    cert->getSigner()->setCaSerial(serial);
	}	
    }
    // check CA serial of this cert
    // FIXME: serial = certs->searchSerial(cert);
    if ( serial > 0L) {
	QMessageBox::information(this,tr(XCA_TITLE),
		tr("The certificate CA serial is lower than the highest serial of one signed certificate it will be set to ") +
		QString::number(serial.getLong()), "OK");
	cert->setCaSerial(serial);
    }
    db->updatePKI(cert);
    return cert;
}

#define P7_ONLY 0
#define P7_CHAIN 1
#define P7_TRUSTED 2

void CertView::store()
{
	QStringList filt;
	pki_x509 *crt = (pki_x509 *)getSelected();
	pki_x509 *oldcrt = NULL;
	emit init_database();
	if (!crt) return;
	pki_key *privkey = crt->getRefKey();
	ExportCert *dlg = new ExportCert((crt->getIntName() + ".crt"),
			  (privkey && privkey->isPrivKey()), MainWindow::getPath(), crt->tinyCAfname() );
	dlg->image->setPixmap(*MainWindow::certImg);
	int dlgret = dlg->exec();

	if (!dlgret) {
		delete dlg;
		return;
	}
	QString fname = dlg->filename->text();
        if (fname == "") {
                delete dlg;
                return;
        }
	try {
	    switch (dlg->exportFormat->currentItem()) {
		case 0: // PEM
			crt->writeCert(fname,true,false);
			break;
		case 1: // PEM with chain
			while(crt && crt != oldcrt) {
				crt->writeCert(fname,true,true);
				oldcrt = crt;
				crt = crt->getSigner();
			}
			break;
		case 2: // PEM all trusted Certificates
			// FIXME: db->writeAllCerts(fname,true);
			break;
		case 3: // PEM all Certificates
			// FIXME: db->writeAllCerts(fname,false);
			break;
		case 4: // DER	
			crt->writeCert(fname,false,false);
			break;
		case 5: // P7 lonely
			writePKCS7(fname, P7_ONLY);
			break;
		case 6: // P12
			writePKCS7(fname, P7_CHAIN);
			break;
		case 7: // P12
			writePKCS7(fname, P7_TRUSTED);
			break;
		case 8: // P12
			writePKCS12(fname,false);
			break;
		case 9: // P12 + cert chain
			writePKCS12(fname,true);
			break;

	    }
	}
	catch (errorEx &err) {
		Error(err);
	}
	delete dlg;
}


void CertView::writePKCS12(QString s, bool chain)
{
	QStringList filt;
    try {
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	pki_key *privkey = cert->getRefKey();
	if (!privkey || privkey->isPubKey()) {
		QMessageBox::warning(this,tr(XCA_TITLE),
                	tr("There was no key found for the Certificate: ") +
			cert->getIntName() );
		return; 
	}
	if (s.isEmpty()) return;
	s = QDir::convertSeparators(s);
	pki_pkcs12 *p12 = new pki_pkcs12(cert->getIntName(), cert, privkey, &MainWindow::passWrite);
	pki_x509 *signer = cert->getSigner();
	int cnt =0;
	while ((signer != NULL ) && (signer != cert) && chain) {
		CERR("SIGNER:"<<(int)signer);
		p12->addCaCert(signer);
		CERR( "signer: " << ++cnt );
		cert=signer;
		signer=signer->getSigner();
	}
	CERR("start writing" );
	p12->writePKCS12(s);
	delete p12;
    }
    catch (errorEx &err) {
	    Error(err);
    }
}

void CertView::writePKCS7(QString s, int type)
{
    pki_pkcs7 *p7 = NULL;
    QList<pki_base> list;
    pki_x509 *cert = (pki_x509 *)getSelected();
    pki_base *cer;
    emit init_database();
    try {	
	p7 =  new pki_pkcs7("");
	if ( type == P7_CHAIN ) {
		while (cert != NULL) {
			p7->addCert(cert);
			if (cert->getSigner() == cert) cert = NULL;
			else cert = cert->getSigner();
		}
	}
	if ( type == P7_ONLY ) {
		p7->addCert(cert);
	}	
	if (type == P7_TRUSTED) {
		list = db->getContainer();
		if (!list.isEmpty()) {
       			for ( cer = list.first(); cer != NULL; cer = list.next() ) {
				p7->addCert((pki_x509 *)cer);
			}
		}
	}
	p7->writeP7(s, false);
    }
    catch (errorEx &err) {
	    Error(err);
    }
    if (p7 != NULL ) delete p7;
	
}
		
void CertView::signP7()
{
	QStringList filt;
    try {
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	pki_key *privkey = cert->getRefKey();
	if (!privkey || privkey->isPubKey()) {
		QMessageBox::warning(this,tr(XCA_TITLE),
                	tr("There was no key found for the Certificate: ") +
			cert->getIntName());
		return; 
	}
        filt.append("All Files ( *.* )");
	QString s="";
	QStringList slist;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Import Certificate signing request"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
        dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
        }
	delete dlg;
	pki_pkcs7 * p7 = new pki_pkcs7("");
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		p7->signFile(cert, s);
		p7->writeP7((s + ".p7s"), true);
	}
	delete p7;
    }
    catch (errorEx &err) {
	Error(err);
    }
}	

void CertView::encryptP7()
{
	QStringList filt;
    try {
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	pki_key *privkey = cert->getRefKey();
	if (!privkey || privkey->isPubKey()) {
		QMessageBox::warning(this,tr(XCA_TITLE),
                	tr("There was no key found for the Certificate: ") +
			cert->getIntName()) ;
		return; 
	}
        filt.append("All Files ( *.* )");
	QString s="";
	QStringList slist;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Import Certificate signing request"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
        dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
        }
	delete dlg;
	pki_pkcs7 * p7 = new pki_pkcs7("");
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		p7->encryptFile(cert, s);
		p7->writeP7((s + ".p7m"), true);
	}
	delete p7;
    }
    catch (errorEx &err) {
	Error(err);
    }
}	

void CertView::popupMenu(QListViewItem *item, const QPoint &pt, int x) {
	CERR( "popup Cert");
	QPopupMenu *menu = new QPopupMenu(this);
	QPopupMenu *subCa = new QPopupMenu(this);
	QPopupMenu *subP7 = new QPopupMenu(this);
	QPopupMenu *subExport = new QPopupMenu(this);
	int itemExtend, itemRevoke, itemTrust, itemCA, itemTemplate, itemReq, itemP7, itemtca;
	bool canSign, parentCanSign, hasTemplates, hasPrivkey;
	
	emit init_database();
	if (!item) {
		menu->insertItem(tr("New Certificate"), this, SLOT(newCert()));
		menu->insertItem(tr("Import"), this, SLOT(loadCert()));
		menu->insertItem(tr("Import PKCS#12"), this, SLOT(loadPKCS12()));
		menu->insertItem(tr("Import from PKCS#7"), this, SLOT(loadPKCS7()));
	}
	else {
		pki_x509 *cert = (pki_x509 *)db->getByName(item->text(0));
		menu->insertItem(tr("Rename"), this, SLOT(startRenameCert()));
		menu->insertItem(tr("Show Details"), this, SLOT(showDetailsCert()));
		menu->insertItem(tr("Export"), subExport);
		subExport->insertItem(tr("File"), this, SLOT(writeCert()));
		itemReq = subExport->insertItem(tr("Request"), this, SLOT(toRequest()));
		itemtca = subExport->insertItem(tr("TinyCA"), this, SLOT(toTinyCA()));

		menu->insertItem(tr("Delete"), this, SLOT(deleteCert()));
		itemTrust = menu->insertItem(tr("Trust"), this, SLOT(setTrust()));
		menu->insertSeparator();
		itemCA = menu->insertItem(tr("CA"), subCa);
		subCa->insertItem(tr("Serial"), this, SLOT(setSerial()));
		subCa->insertItem(tr("CRL days"), this, SLOT(setCrlDays()));
		itemTemplate = subCa->insertItem(tr("Signing Template"), this, SLOT(setTemplate()));
		subCa->insertItem(tr("Generate CRL"), this, SLOT(genCrl()));
		
		itemP7 = menu->insertItem(tr("PKCS#7"), subP7);
		subP7->insertItem(tr("Sign"), this, SLOT(signP7()));
		subP7->insertItem(tr("Encrypt"), this, SLOT(encryptP7()));
		menu->insertSeparator();
		itemExtend = menu->insertItem(tr("Renewal"), this, SLOT(extendCert()));
		if (cert) {
			if (cert->isRevoked()) {
				itemRevoke = menu->insertItem(tr("Unrevoke"), this, SLOT(unRevoke()));
				menu->setItemEnabled(itemTrust, false);
			}
			else	
				itemRevoke = menu->insertItem(tr("Revoke"), this, SLOT(revoke()));
			parentCanSign = (cert->getSigner() && cert->getSigner()->canSign() && (cert->getSigner() != cert));
			canSign = cert->canSign();
			hasTemplates = MainWindow::temps->getDesc().count() > 0 ;
			hasPrivkey = cert->getRefKey();
		}
		menu->setItemEnabled(itemExtend, parentCanSign);
		menu->setItemEnabled(itemRevoke, parentCanSign);
		menu->setItemEnabled(itemCA, canSign);
		subExport->setItemEnabled(itemReq, hasPrivkey);
		subExport->setItemEnabled(itemtca, canSign);
		menu->setItemEnabled(itemP7, hasPrivkey);
		subCa->setItemEnabled(itemTemplate, hasTemplates);

	}
	menu->exec(pt);
	delete menu;
	delete subCa;
	delete subP7;
	delete subExport;
	
	return;
}

void CertView::setTrust()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	TrustState_UI *dlg = new TrustState_UI(this,0,true);
	int state, newstate;
	state = cert->getTrust();
	if (cert->getSigner() == cert) {
		if (state == 1) state = 0;
		dlg->trust1->setDisabled(true);
	}
	if (state == 0 ) dlg->trust0->setChecked(true);
	if (state == 1 ) dlg->trust1->setChecked(true);
	if (state == 2 ) dlg->trust2->setChecked(true);
	dlg->certName->setText(cert->getIntName());
	if (dlg->exec()) {
		if (dlg->trust0->isChecked()) newstate = 0;
		if (dlg->trust1->isChecked()) newstate = 1;
		if (dlg->trust2->isChecked()) newstate = 2;
		if (newstate!=state) {
			cert->setTrust(newstate);
			db->updatePKI(cert);
			updateView();
		}
	}
	delete dlg;
}

void CertView::toRequest()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	try {
		pki_x509req *req = new pki_x509req();
		req->createReq(cert->getRefKey(), cert->getSubject());
                // FIXME: insert(req);
	}
	catch (errorEx &err) {
		Error(err);
	}
	
}

void CertView::revoke()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	cert->setRevoked(true);
	CERR("setRevoked..." );
	db->updatePKI(cert);
	CERR("updatePKI done");
	updateView();
	CERR("view updated");
}

void CertView::unRevoke()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	cert->setRevoked(false);
	db->updatePKI(cert);
	updateView();
}

void CertView::setSerial()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	a1int serial = cert->getCaSerial();
	bool ok;
	a1int nserial = QInputDialog::getInteger (tr(XCA_TITLE),
			tr("Please enter the new Serial for signing"),
			serial.getLong(), serial.getLong(), 2147483647, 1, &ok, this );
	if (ok && nserial > serial) {
		cert->setCaSerial(nserial);
		db->updatePKI(cert);
	}
}

void CertView::setCrlDays()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	int crlDays = cert->getCrlDays();
	bool ok;
	int nCrlDays = QInputDialog::getInteger (tr(XCA_TITLE),
			tr("Please enter the CRL renewal periode in days"),
			crlDays, 1, 2147483647, 1, &ok, this );
	if (ok && (crlDays != nCrlDays)) {
		cert->setCrlDays(nCrlDays);
		db->updatePKI(cert);
	}
}

void CertView::setTemplate()
{
	pki_x509 *cert = (pki_x509 *)getSelected();
	if (!cert) return;
	QString templ = cert->getTemplate();
	QStringList tempList = MainWindow::temps->getDesc();
	unsigned int i, sel=0;
	bool ok;
	for (i=0; i<tempList.count(); i++) {
		if (tempList[i] == templ) {
			sel = i;
		}
	}
	QString nTempl = QInputDialog::getItem (tr(XCA_TITLE),
			tr("Please select the default Template for signing"),
			tempList, sel, false, &ok, this );
	if (ok && (templ != nTempl)) {
		cert->setTemplate(nTempl);
		db->updatePKI(cert);
	}
}


void CertView::changeView()
{
	if (viewState == 0) { // Plain view
		viewState = 1;
		// FIXME: bnViewState->setText(tr("Plain View"));
	}
	else { // Tree View
		viewState = 0;
		// FIXME: bnViewState->setText(tr("Tree View"));
	}
	updateView();
}

#define fopenerror(file) \
	QMessageBox::warning(this,tr(XCA_TITLE), \
       		tr("The file '") + file + tr("' could not be opened"));

void CertView::toTinyCA()
{
#ifndef WIN32
	pki_x509 *crt = (pki_x509 *)getSelected();
	if (!crt) return;
	pki_key *key = crt->getRefKey();
	if (!key) return;
	FILE *fp, *fpr;
	char buf[200];
	QList<pki_x509> list;
	pki_x509 *issuedcert;
	QString dname = crt->getIntName();
	QString tcatempdir = MainWindow::settings->getString("TinyCAtempdir");
	QString tcadir = MainWindow::settings->getString("TinyCAdir");
	if (tcatempdir.isEmpty()) {
		tcatempdir = "templates";
	}
	if (tcadir.isEmpty()) {
		tcadir = QDir::homeDirPath();
		tcadir += QDir::separator();
		tcadir += ".TinyCA";
	}
	ExportTinyCA *dlg = new ExportTinyCA( tcatempdir, tcadir, this, NULL);
	if (!dlg->exec()) return;
	
	tcatempdir = dlg->tempdir->text();
	tcadir = dlg->tinycadir->text();
	dname = dlg->dname->text();
	
	MainWindow::settings->putString("TinyCAtempdir", tcatempdir);
	MainWindow::settings->putString("TinyCAdir", tcadir);
	
	if (dname.isEmpty()) return;
	const EVP_CIPHER *enc = EVP_des_ede3_cbc();
	
	
	// OK, we have all names now...
	tcadir += QDir::separator();
        tcadir += dname;
	
	//create directory tree
	if (! mkDir(tcadir)) return;
	chdir(tcadir);
	if (! mkDir("certs")) return;
	if (! mkDir("crl")) return;
	if (! mkDir("keys")) return;
	if (! mkDir("newcerts")) return;
	if (! mkDir("req")) return;
	
	// write the CA cert and key
	crt->writeCert("cacert.pem", true, false);
	key->writeKey("cacert.key", enc, &MainWindow::passWrite, true);
	// write the crl
	chdir("crl");
	pki_crl *crl; // FIXME:  = genCrl(crt);
	crl->writeCrl("crl.pem");
	delete crl;
	chdir("..");
	// write the serial
	fp = fopen("serial", "w");
	if (!fp) {
		fopenerror("serial");
		return;
	}
	fprintf(fp, "%08lx", crt->getCaSerial().getLong());
	fclose(fp);
	
	// copy openssl.cnf
	tcatempdir += QDir::separator();
	tcatempdir += "openssl.cnf";
	fpr = fopen(tcatempdir, "r");
	if (!fpr) {
		fopenerror("openssl.cnf" );
		return;
	}
	fp = fopen("openssl.cnf", "w");
	if (!fp) {
		fopenerror("openssl.cnf" );
		fclose(fpr);
		return;
	}
	while (fgets(buf ,200, fpr) != NULL) {
		char *x = strstr(buf,"%dir%");
		if (x != 0) {
			x[0]='\0';
			fputs(buf, fp);
			fputs(tcadir, fp);
			fputs(x+5, fp);
		}
		else {
			fputs(buf, fp);
		}
	}
	fclose(fp);
	fclose(fpr);
	
	// store the issued certificates
	fp = fopen("index.txt", "w");
        if (!fp) return;
	list = ((db_x509 *)db)->getIssuedCerts(crt);
	if (!list.isEmpty()) {
       		for ( issuedcert = list.first(); issuedcert != NULL; issuedcert = list.next() ) {
			QString fname = issuedcert->tinyCAfname();
			chdir("certs");
			crt->writeCert(fname, true, false);
			chdir("..");
			key = issuedcert->getRefKey();
			if (key) {
				chdir("keys");
				key->writeKey(fname, NULL, &MainWindow::passWrite, true);
				chdir("..");
			}
			fprintf(fp, "%c\t%s\t%s\t%s\tunknown\t%s\n", 
					issuedcert->isRevoked() ? 'R':'V', 
					issuedcert->getNotAfter().toPlain().latin1(),
					issuedcert->getRevoked().toPlain().latin1(),
					issuedcert->getSerial().toHex().latin1(), 
					issuedcert->getSubject().oneLine().latin1() );
			
		}
	}
	fclose(fp);
	
#endif	
}	

bool CertView::updateView()
{
        clear();
        setRootIsDecorated(true);
        pki_x509 *pki;
        pki_base *pkib;
        pki_x509 *signer;
        QListViewItem *parentitem;
        QListViewItem *current;
        CERR("myUPDATE");
        QList<pki_base> container = db->getContainer();
	if ( container.isEmpty() ) return false;
        QList<pki_base> mycont = container;
        for ( pkib = container.first(); pkib != NULL; pkib = container.next() ) pkib->delLvi();
        int f=0;
        while (! mycont.isEmpty() ) {
                CERR("-----------------------------------------------------------------Round "<< f++);
                QListIterator<pki_base> it(mycont);
                for ( ; it.current(); ++it ) {
                        pki = (pki_x509 *)it.current();
                        parentitem = NULL;
                        signer = pki->getSigner();
                        if ((signer != pki) && (signer != NULL) && (viewState != 0)) // foreign signed
                                parentitem = signer->getLvi();
                        if (((parentitem != NULL) || (signer == pki) || (signer == NULL) || viewState == 0) && (pki->getLvi() == NULL )) {
                                // create the listview item
                                if (parentitem != NULL) {
                                        current = new QListViewItem(parentitem, pki->getIntName());
                                        CERR("Adding as client: "<<pki->getIntName());
                                }
                                else {
                                        current = new QListViewItem(this, pki->getIntName());
                                        CERR("Adding as parent: "<<pki->getIntName());
                                }
                                pki->setLvi(current);
                                mycont.remove(pki);
                                updateViewItem(pki);
                                it.toFirst();
                        }
                }

        }
        return true;
}

bool CertView::mkDir(QString dir)
{
#ifdef WIN32
        int ret = mkdir(dir.latin1());
        // in direct.h declare _CRTIMP int __cdecl mkdir(const char *);
#else
        int ret = mkdir(dir.latin1(), S_IRUSR | S_IWUSR | S_IXUSR);
#endif
        if (ret) {
                QString desc = " (";
                desc += strerror(ret);
                desc += ")";
                QMessageBox::critical(this,tr(XCA_TITLE),
                        tr("Error creating: ") + dir + desc);
                return false;
        }
        return true;

}

void CertView::updateViewItem(pki_base *pki)
{
	XcaListView::updateViewItem(pki);
	if (! pki) return;
	QString truststatus[] = { tr("Not trusted"), tr("Trust inherited"), tr("Always Trusted") };
	int pixnum = 0;
	QListViewItem *current = pki->getLvi();
	if (!current) return;
	if (((pki_x509 *)pki)->getRefKey()) {
		pixnum += 1;
	}
	if (((pki_x509 *)pki)->calcEffTrust() == 0){ 
		pixnum += 2;
	}	
	current->setPixmap(0, *certicon[pixnum]);
	current->setText(1, ((pki_x509 *)pki)->getSubject().getEntryByNid(NID_commonName));
	current->setText(2, ((pki_x509 *)pki)->getSerial().toHex() );  
	current->setText(3, ((pki_x509 *)pki)->getNotAfter().toSortable() );  
	current->setText(4, truststatus[((pki_x509 *)pki)->getTrust() ]);  
	current->setText(5, ((pki_x509 *)pki)->getRevoked().toSortable());
}

void CertView::updateViewAll()
{
	emit init_database();
	QList<pki_base> c = db->getContainer();
	for (pki_x509 *pki = (pki_x509 *)c.first(); pki != 0; pki = (pki_x509 *)c.next() ) 
		updateViewItem(pki);
	return;
}

