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


#include "MainWindow.h"

void MainWindow::newCert()
{
	NewX509 *dlg = new NewX509(this, NULL, keys, reqs, certs, temps, certImg, nsImg );
	dlg->setCert();
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void MainWindow::newCert(pki_temp *templ)
{
	NewX509 *dlg = new NewX509(this, NULL, keys, reqs, certs, temps, certImg, nsImg );
	if (templ) {
		dlg->defineTemplate(templ);
	}
	dlg->setCert();
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void MainWindow::newCert(pki_x509req *req)
{
	NewX509 *dlg = new NewX509(this, NULL, keys, reqs, certs, temps, certImg, nsImg );
	if (req) {
		dlg->defineRequest(req);
	}
	dlg->setCert();
	if (dlg->exec()) {
		newCert(dlg);
	}
	delete dlg;
}

void MainWindow::newCert(NewX509 *dlg)
{
	pki_x509 *cert = NULL;
	pki_x509 *signcert = NULL;
	pki_x509req *req = NULL;
	pki_key *signkey = NULL, *clientkey = NULL;
	int serial = 42; // :-)
	bool tempReq=false;
	int i, x, days;
	string cont="", subAltName="", issAltName="", constraints="",
		keyuse="", keyuse1="", pathstr="", certTypeStr = "";
	char *ekeyusage[]= {"serverAuth","clientAuth","codeSigning","emailProtection",
		"timeStamping","msCodeInd","msCodeCom",
		"msCTLSign","msSGC","msEFS","nsSGC"};
	char *keyusage[] ={"digitalSignature", "nonRepudiation", "keyEncipherment",
		"dataEncipherment", "keyAgreement", "keyCertSign",
		"cRLSign", "encipherOnly", "decipherOnly"};
	char *certTypeList[] = { "client", "server", "email", "objsign",
				 "sslCA", "emailCA", "objCA" };
	QListBoxItem *item;
	

    try {	
	// Step 1 - Subject and key
	if (!dlg->fromReqCB->isChecked()) {
	    clientkey = (pki_key *)keys->getSelectedPKI(dlg->keyList->currentText().latin1());
	    string cn = dlg->commonName->text().latin1();
	    string c = dlg->countryName->text().latin1();
	    string l = dlg->localityName->text().latin1();
	    string st = dlg->stateOrProvinceName->text().latin1();
	    string o = dlg->organisationName->text().latin1();
	    string ou = dlg->organisationalUnitName->text().latin1();
	    string email = dlg->emailAddress->text().latin1();
	    string desc = dlg->description->text().latin1();
	    tempReq = true;
	    req = new pki_x509req(clientkey, cn,c,l,st,o,ou,email,desc,"");
	}
	else {
	    // A PKCS#10 Request was selected 
	    req = (pki_x509req *)reqs->getSelectedPKI(dlg->reqList->currentText().latin1());
	    if (opensslError(req)) return;
	    clientkey = req->getKey();
	}
		
	// Step 2 - select Signing
	if (dlg->foreignSignRB->isChecked()) {
		signcert = (pki_x509 *)certs->getSelectedPKI(dlg->certList->currentText().latin1());
		signkey = signcert->getKey();
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
	x = dlg->validNumber->text().toInt();
	days = dlg->validRange->currentItem();
	if (days == 1) x *= 30;
	if (days == 2) x *= 365;
	
	// increase serial here	
	if (dlg->foreignSignRB->isChecked()) {
		serial = signcert->getIncCaSerial();
		// get own serial to avoid having the same
		if (serial == atoi(signcert->getSerial().c_str())) { // FIXME: anybody tell me the string method for this ?
			serial = signcert->getIncCaSerial(); // just take the next one
		}
		certs->updatePKI(signcert);  // not so pretty ....
		CERR("serial is: " << serial );
	}	
	
	// initially create cert 
	cert = new pki_x509(req->getDescription(), clientkey, req, signcert, x, serial);
	if (!signcert) signcert=cert;	
	if (cert->resetTimes(signcert) > 0) {
		if (QMessageBox::information(this,tr(XCA_TITLE),
			tr("The validity times for the certificate need to get adjusted to not exceed those of the signer"),
			tr("Continue creation"), tr("Abort")
		))
			throw errorEx("");
	}
			
	// handle extensions
	// basic constraints
	if (dlg->bcCritical->isChecked()) constraints = "critical,";
	constraints +="CA:";
	constraints += dlg->basicCA->currentText().latin1();
	pathstr = dlg->basicPath->text().latin1();
	if (pathstr.length()>0) {
		constraints += ", pathlen:";
		constraints += pathstr;
	}
	cert->addV3ext(NID_basic_constraints, constraints);
	// Subject Key identifier
	if (dlg->subKey->isChecked()) {
		string subkey="hash";
		cert->addV3ext(NID_subject_key_identifier, subkey);
		CERR( subkey );
	}
	// Authority Key identifier
	if (dlg->authKey->isChecked()) {
		string authkey="keyid:always,issuer:always";
		cert->addV3ext(NID_authority_key_identifier, authkey);
		CERR( authkey );
	}
	 
	// key usage
	for (i=0; (item = dlg->keyUsage->item(i)); i++) {	
		if (item->selected()){
			addStr(keyuse, keyusage[i]);
		}
	}
	
	if (keyuse.length() > 0) {
		keyuse1 = keyuse;
		if (dlg->kuCritical->isChecked()) keyuse1 = "critical, " +keyuse;
		cert->addV3ext(NID_key_usage, keyuse1);
		CERR( "KeyUsage:" <<keyuse1);
	}
	
	// extended key usage
	keyuse=""; keyuse1="";
	for (i=0; (item = dlg->ekeyUsage->item(i)); i++) {	
		if (item->selected()){
			addStr(keyuse, ekeyusage[i]);
		}
	}
	
	if (keyuse.length() > 0) {
		keyuse1 = keyuse;
		if (dlg->ekuCritical->isChecked()) keyuse1 = "critical, " +keyuse;
		cert->addV3ext(NID_ext_key_usage, keyuse1);
		CERR( "Extended Key Usage:" <<keyuse1 );
	}
	
	
	// STEP 4
	// Subject Alternative name
	cont = "";
	cont = dlg->subAltName->text().latin1();
	if (dlg->subAltCp->isChecked()) {
		if (req->getDN(NID_pkcs9_emailAddress).length() == 0) {
			if (QMessageBox::information(this,tr(XCA_TITLE),
			   tr("You requested to copy the subject E-Mail address but it is empty !"),
			   tr("Continue creation"), tr("Abort")
			))
				throw errorEx("");	
		}
		else {
			subAltName = "email:copy";
		}
	}
	if (cont.length() > 0){
		addStr(subAltName,cont.c_str());
	}
	if (subAltName.length() > 0) {
		CERR( "SubAltName:" << subAltName);
		cert->addV3ext(NID_subject_alt_name, subAltName);
	}
	
	cont = "";
	cont = dlg->issAltName->text().latin1();
	// issuer alternative name	
	if (dlg->issAltCp->isChecked()) {
		if (!signcert->hasSubAltName()) {
			if (QMessageBox::information(this,tr(XCA_TITLE),
			   tr("You requested to copy the issuer alternative name but it is empty !"),
			   tr("Continue creation"), tr("Abort")
			))
				throw errorEx("");	
		}
		else {
			issAltName = "issuer:copy";
		}
	}
	if (cont.length() > 0){
		addStr(issAltName,cont.c_str());
	}
	if (issAltName.length() > 0) {
		CERR("IssAltName:" << issAltName);
		cert->addV3ext(NID_issuer_alt_name, issAltName);
	}
	// CRL distribution points
	if (!dlg->crlDist->text().isEmpty()) {
		CERR("CRL dist. Point: "<<  dlg->crlDist->text().latin1() );
		cert->addV3ext(NID_crl_distribution_points, dlg->crlDist->text().latin1());
	}
		
	// Step 5
	// Nestcape extensions 
	for (i=0; (item = dlg->nsCertType->item(i)); i++) {	
		if (item->selected()){
			addStr(certTypeStr, certTypeList[i]);
		}
	}
	cert->addV3ext(NID_netscape_cert_type, certTypeStr);
	cert->addV3ext(NID_netscape_base_url, dlg->nsBaseUrl->text().latin1());
	cert->addV3ext(NID_netscape_revocation_url, dlg->nsRevocationUrl->text().latin1());
	cert->addV3ext(NID_netscape_ca_revocation_url, dlg->nsCARevocationUrl->text().latin1());
	cert->addV3ext(NID_netscape_renewal_url, dlg->nsRenewalUrl->text().latin1());
	cert->addV3ext(NID_netscape_ca_policy_url, dlg->nsCaPolicyUrl->text().latin1());
	cert->addV3ext(NID_netscape_ssl_server_name, dlg->nsSslServerName->text().latin1());
	cert->addV3ext(NID_netscape_comment, dlg->nsComment->text().latin1());
	
	// and finally sign the request 
	cert->sign(signkey);
	CERR( "SIGNED");
	insertCert(cert);
	CERR("inserted");
	if (tempReq && req) delete(req);
	CERR("Dialog deleted" );
	keys->updateView();
	return;
    }
    catch (errorEx &err) {
	Error(err);
    }
	
}
void MainWindow::addStr(string &str, const  char *add)
{
	string sadd = add;
	if (sadd.length() == 0) return;	
	if (str.length() > 0 ) {
		str += ", ";
	}
	str += add;
}

void MainWindow::extendCert()
{
	pki_x509 *oldcert = NULL, *signer = NULL, *newcert =NULL;
	pki_key *signkey = NULL;
	int serial, days, x;
	try {
		CertExtend_UI *dlg = new CertExtend_UI(this, NULL);
		dlg->image->setPixmap(*certImg);
		if (!dlg->exec()) {
			delete dlg;
			return;
		}
		oldcert = (pki_x509 *)certs->getSelectedPKI();
		if (!oldcert || !(signer = oldcert->getSigner()) || !(signkey = signer->getKey()) || signkey->isPubKey()) return;
		newcert = new pki_x509(oldcert);
		serial = signer->getIncCaSerial();
		
		// get signers own serial to avoid having the same
		if (serial == atoi(signer->getSerial().c_str())) { // FIXME: anybody tell me the string method for this ?
			serial = signer->getIncCaSerial(); // just take the next one
		}
		certs->updatePKI(signer);  // not so pretty ....
		CERR("serial is: " << serial );
		
		// Date handling
		x = dlg->validNumber->text().toInt();
		days = dlg->validRange->currentItem();
		if (days == 1) x *= 30;
		if (days == 2) x *= 365;
		
		// change date and serial
		newcert->setSerial(serial);
		newcert->setDates(x); // now and now + x days

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
		insertCert(newcert);
		CERR("inserted");
		delete dlg;
	}
	catch (errorEx &err) {
		Error(err);
	}
}
		
	
void MainWindow::showDetailsCert()
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
        showDetailsCert(cert);
}

void MainWindow::showDetailsCert(QListViewItem *item)
{
	string cert = item->text(0).latin1();
        showDetailsCert((pki_x509 *)certs->getSelectedPKI(cert));
}


bool MainWindow::showDetailsCert(pki_x509 *cert, bool import)
{
	if (!cert) return false;
	if (opensslError(cert)) return false;
    try {
	CertDetail_UI *dlg = new CertDetail_UI(this,0,true);
	dlg->image->setPixmap(*certImg);
	dlg->descr->setText(cert->getDescription().c_str());
	dlg->setCaption(tr(XCA_TITLE));

	// examine the key
	pki_key *key= cert->getKey();
	if (key)
	     if (key->isPrivKey()) {
		dlg->privKey->setText(key->getDescription().c_str());
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
		dlg->verify->setText(cert->getSigner()->getDescription().c_str());
	}

	// check trust state
	if (cert->getEffTrust() == 0) {
	      	dlg->verify->setDisabled(true);
	}
	CERR( cert->getEffTrust() );
	
	// the serial
	dlg->serialNr->setText(cert->getSerial().c_str());	

	// details of subject
	string land = cert->getDNs(NID_countryName);
	string land1 = cert->getDNs(NID_stateOrProvinceName);
	if (land != "" && land1 != "")
		land += " / " +land1;
	else
		land+=land1;
	dlg->dnCN->setText(cert->getDNs(NID_commonName).c_str() );
	dlg->dnC->setText(land.c_str());
	dlg->dnL->setText(cert->getDNs(NID_localityName).c_str());
	dlg->dnO->setText(cert->getDNs(NID_organizationName).c_str());
	dlg->dnOU->setText(cert->getDNs(NID_organizationalUnitName).c_str());
	dlg->dnEmail->setText(cert->getDNs(NID_pkcs9_emailAddress).c_str());
	
	// same for issuer....	
	land = cert->getDNi(NID_countryName);
	land1 = cert->getDNi(NID_stateOrProvinceName);
	if (land != "" && land1 != "")
		land += " / " +land1;
	else
		land+=land1;
	dlg->dnCN_2->setText(cert->getDNi(NID_commonName).c_str() );
	dlg->dnC_2->setText(land.c_str());
	dlg->dnL_2->setText(cert->getDNi(NID_localityName).c_str());
	dlg->dnO_2->setText(cert->getDNi(NID_organizationName).c_str());
	dlg->dnOU_2->setText(cert->getDNi(NID_organizationalUnitName).c_str());
	dlg->dnEmail_2->setText(cert->getDNi(NID_pkcs9_emailAddress).c_str());
	dlg->notBefore->setText(cert->notBefore().c_str());
	dlg->notAfter->setText(cert->notAfter().c_str());

	// validation of the Date
	if (cert->checkDate() == -1) {
		dlg->dateValid->setText(tr("Not valid"));
	      	dlg->dateValid->setDisabled(true);
	}
	if (cert->checkDate() == +1) {
		dlg->dateValid->setText(tr("Not valid"));
	      	dlg->dateValid->setDisabled(true);
	}
	string revdate = cert->revokedAt();
	if (revdate != "") {
		dlg->dateValid->setText(tr("Revoked: ")+ revdate.c_str());
	      	dlg->dateValid->setDisabled(true);
		
	}
	// the fingerprints
	dlg->fpMD5->setText(cert->fingerprint(EVP_md5()).c_str());
	dlg->fpSHA1->setText(cert->fingerprint(EVP_sha1()).c_str());
	
	// V3 extensions
	dlg->v3Extensions->setText(cert->printV3ext().c_str());
	
	// rename the buttons in case of import 
	if (import) {
		dlg->but_ok->setText(tr("Import"));
		dlg->but_cancel->setText(tr("Discard"));
	}

	// show it to the user...	
	if (dlg->exec()) {
		string ndesc = dlg->descr->text().latin1();
		if (ndesc != cert->getDescription()) {
			certs->renamePKI(cert, ndesc);
		}
		delete dlg;
		return true;
	}
	delete dlg;
	return false;
    }
    catch (errorEx &err) {
	    Error(err);
    }
    return false;
}

void MainWindow::deleteCert()
{
    try {
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	if (cert->getSigner() && cert->getSigner() != cert && cert->getSigner()->canSign()) {
		QMessageBox::information(this,tr(XCA_TITLE),
			tr("It is actually not a good idea to delete a cert that was signed by you") +":\n'" + 
			QString::fromLatin1(cert->getDescription().c_str()) + "'\n" ,
			tr("Ok") );
	 		return;
	}
	if (QMessageBox::information(this,tr(XCA_TITLE),
			tr("Really want to delete the Certificate") +":\n'" + 
			QString::fromLatin1(cert->getDescription().c_str()) + "'\n" ,
			tr("Delete"), tr("Cancel") )
	) return;
	pki_key *pkey = cert->getKey();
	certs->deletePKI(cert);
	if (pkey) keys->updateViewPKI(pkey);
    }
    catch (errorEx &err) {
	    Error(err);
    }
}

void MainWindow::loadCert()
{
	QStringList filt;
	filt.append(tr("Certificates ( *.pem *.der *.crt *.cer)")); 
	filt.append(tr("PKCS#12 Certificates ( *.p12 )")); 
	//filt.append(tr("PKCS#7 Signatures ( *.p7s )")); 
	filt.append(tr("All files ( *.* )"));
	QStringList slist;
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate import"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
	setPath(dlg);
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		newPath(dlg);
	}
	delete dlg;
	
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		try {
			pki_x509 *cert = new pki_x509(s.latin1());
			insertCert(cert);
			keys->updateViewPKI(cert->getKey());
		}
		catch (errorEx &err) {
			Error(err);
		}
	}
		
}

void MainWindow::loadPKCS12()
{
	pki_pkcs12 *pk12;
	pki_x509 *acert;
	pki_key *akey;
	QStringList filt;
	filt.append(tr("PKCS#12 Certificates ( *.p12 )")); 
	filt.append(tr("All files ( *.* )"));
	QStringList slist;
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate import"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::ExistingFiles );
	setPath(dlg);
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		newPath(dlg);
	}
	delete dlg;
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		s = *it;
		s = QDir::convertSeparators(s);
		try {
			pk12 = new pki_pkcs12(s.latin1(), &MainWindow::passRead);
			akey = pk12->getKey();
			acert = pk12->getCert();
			insertKey(akey);
			insertCert(acert);
			for (int i=0; i<pk12->numCa(); i++) {
				acert = pk12->getCa(i);
				insertCert(acert);
			}
			delete pk12;
			keys->updateView();
		}
		catch (errorEx &err) {
			Error(err);
		}
	}

	
/* insert with asking.....	
	if (showDetailsKey(akey, true)) {
		insertKey(akey);
	}
	else {
		delete(akey);
	}
	if (showDetailsCert(acert,true)) {
		insertCert(acert);
	}
	else {
		delete(acert);
	}
	for (int i=0; i<pk12->numCa(); i++) {
		acert = pk12->getCa(i);
		if (showDetailsCert(acert, true)) {
			insertCert(acert);
		}
		else {
			delete(acert);
		}
	}
*/
}	
	
void MainWindow::insertCert(pki_x509 *cert)
{
    try {
	pki_x509 *oldcert = (pki_x509 *)certs->findPKI(cert);
	if (oldcert) {
	   QMessageBox::information(this,tr(XCA_TITLE),
		tr("The certificate already exists in the database as") +":\n'" +
		QString::fromLatin1(oldcert->getDescription().c_str()) + 
		"'\n" + tr("and so it was not imported"), "OK");
	   delete(cert);
	   return;
	}
	CERR( "insertCert: inserting" );
	certs->insertPKI(cert);
    }
    catch (errorEx &err) {
	    Error(err);
    }
    if (cert->getSigner()) {
	int serial = atoi(cert->getSerial().c_str());
    	if (serial >= cert->getSigner()->getCaSerial()) {
	    QMessageBox::information(this,tr(XCA_TITLE),
		tr("The certificate-serial is higher than the next serial of the signer it will be set to ") +
		QString::number(serial + 1), "OK");
	    cert->getSigner()->setCaSerial(serial+1);
	    certs->updatePKI(cert);
	}	
    }
}

void MainWindow::writeCert()
{
	QStringList filt;
	pki_x509 *crt = (pki_x509 *)certs->getSelectedPKI();
	if (!crt) return;
	pki_key *privkey = crt->getKey();
	ExportCert *dlg = new ExportCert((crt->getDescription() + ".crt").c_str(),
			  (privkey->isPrivKey()));
	if (!dlg->exec()) {
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
			crt->writeCert(fname.latin1(),true);
			break;
		case 1: // DER	
			crt->writeCert(fname.latin1(),false);
			break;
		case 2: // P12
			writePKCS12(fname,false);
			break;
		case 3: // P12 + cert chain
			writePKCS12(fname,true);
			break;

	    }
	}
	catch (errorEx &err) {
		Error(err);
	}
	delete dlg;
}


void MainWindow::writePKCS12(QString s, bool chain)
{
	QStringList filt;
    try {
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	pki_key *privkey = cert->getKey();
	if (!privkey || privkey->isPubKey()) {
		QMessageBox::warning(this,tr(XCA_TITLE),
                	tr("There was no key found for the Certificate: ") +
			QString::fromLatin1(cert->getDescription().c_str()) );
		return; 
	}
	if (s.isEmpty()) return;
	s = QDir::convertSeparators(s);
	pki_pkcs12 *p12 = new pki_pkcs12(cert->getDescription(), cert, privkey, &MainWindow::passWrite);
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
	p12->writePKCS12(s.latin1());
	delete p12;
    }
    catch (errorEx &err) {
	    Error(err);
    }
}

void MainWindow::showPopupCert(QListViewItem *item, const QPoint &pt, int x) {
	CERR( "popup Cert");
	QPopupMenu *menu = new QPopupMenu(this);
	QPopupMenu *subCa = new QPopupMenu(this);
	QPopupMenu *subExport = new QPopupMenu(this);
	int itemExtend, itemRevoke, itemTrust, itemCA, itemTemplate, itemReq;
	bool canSign, parentCanSign, hasTemplates, hasPrivkey;
	
	if (!item) {
		menu->insertItem(tr("New Certificate"), this, SLOT(newCert()));
		menu->insertItem(tr("Import"), this, SLOT(loadCert()));
	}
	else {
		pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI(item->text(0).latin1());
		menu->insertItem(tr("Rename"), this, SLOT(startRenameCert()));
		menu->insertItem(tr("Show Details"), this, SLOT(showDetailsCert()));
		menu->insertItem(tr("Export"), subExport);
		subExport->insertItem(tr("File"), this, SLOT(writeCert()));
		itemReq = subExport->insertItem(tr("Request"), this, SLOT(toRequest()));

		menu->insertItem(tr("Delete"), this, SLOT(deleteCert()));
		itemTrust = menu->insertItem(tr("Trust"), this, SLOT(setTrust()));
		menu->insertSeparator();
		itemCA = menu->insertItem(tr("CA"), subCa);
		subCa->insertItem(tr("Serial"), this, SLOT(setSerial()));
		subCa->insertItem(tr("CRL days"), this, SLOT(setCrlDays()));
		itemTemplate = subCa->insertItem(tr("Signing Template"), this, SLOT(setTemplate()));
		subCa->insertItem(tr("Generate CRL"), this, SLOT(genCrl()));
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
			hasTemplates = temps->getDesc().count() > 0 ;
			hasPrivkey = cert->getKey();
		}
		menu->setItemEnabled(itemExtend, parentCanSign);
		menu->setItemEnabled(itemRevoke, parentCanSign);
		menu->setItemEnabled(itemCA, canSign);
		subExport->setItemEnabled(itemReq, hasPrivkey);
		subCa->setItemEnabled(itemTemplate, hasTemplates);

	}
	menu->exec(pt);
	delete menu;
	delete subCa;
	delete subExport;
	
	return;
}

void MainWindow::renameCert(QListViewItem *item, int col, const QString &text)
{
	if (col != 0) return;
	try {
		pki_base *pki = certs->getSelectedPKI(item);
		string txt =  text.latin1();
		certs->renamePKI(pki, txt);
	}
	catch (errorEx &err) {
		Error(err);
	}
}

void MainWindow::setTrust()
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
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
	dlg->certName->setText(cert->getDescription().c_str());
	if (dlg->exec()) {
		if (dlg->trust0->isChecked()) newstate = 0;
		if (dlg->trust1->isChecked()) newstate = 1;
		if (dlg->trust2->isChecked()) newstate = 2;
		if (newstate!=state) {
			cert->setTrust(newstate);
			certs->updatePKI(cert);
			certs->updateViewAll();
		}
	}
	delete dlg;
}

void MainWindow::toRequest()
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	try {
		pki_x509req *req = new pki_x509req(cert);
		insertReq(req);
	}
	catch (errorEx &err) {
		Error(err);
	}
	
}

void MainWindow::revoke()
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	cert->setRevoked(true);
	CERR("setRevoked..." );
	certs->updatePKI(cert);
	CERR("updatePKI done");
	certs->updateViewAll();
	CERR("view updated");
}

void MainWindow::unRevoke()
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	cert->setRevoked(false);
	certs->updatePKI(cert);
	certs->updateViewAll();
}

void MainWindow::setSerial()
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	int serial = cert->getCaSerial();
	bool ok;
	int nserial = QInputDialog::getInteger (tr(XCA_TITLE),
			tr("Please enter the new Serial for signing"),
			serial, serial, 2147483647, 1, &ok, this );
	if (ok && nserial > serial) {
		cert->setCaSerial(nserial);
		certs->updatePKI(cert);
	}
}

void MainWindow::setCrlDays()
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	int crlDays = cert->getCrlDays();
	bool ok;
	int nCrlDays = QInputDialog::getInteger (tr(XCA_TITLE),
			tr("Please enter the CRL renewal periode in days"),
			crlDays, crlDays, 365, 1, &ok, this );
	if (ok && (crlDays != nCrlDays)) {
		cert->setCrlDays(nCrlDays);
		certs->updatePKI(cert);
	}
}

void MainWindow::setTemplate()
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	QString templ = cert->getTemplate().c_str();
	QStringList tempList = temps->getDesc();
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
		cert->setTemplate(nTempl.latin1());
		certs->updatePKI(cert);
	}
}

void MainWindow::genCrl() 
{
	QStringList filt;
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	if (cert->getKey()->isPubKey()) return;
	filt.append(tr("CRLs ( *.crl )")); 
	filt.append(tr("All Files ( *.* )"));
	QString s="";
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("CRL export"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::AnyFile );
	dlg->setSelection( (cert->getDescription() + ".crl").c_str() );
	if (dlg->exec())
		s = dlg->selectedFile();
	delete dlg;
	if (s.isEmpty()) return;
	s = QDir::convertSeparators(s);
	try {	
		pki_crl *crl = new pki_crl(cert->getDescription(), cert);
		certs->assignClients(crl);
		crl->addV3ext(NID_authority_key_identifier,"keyid,issuer");
		//crl->addV3ext(NID_issuer_alt_name,"issuer:copy");
		crl->sign(cert->getKey());
		crl->writeCrl(s.latin1());
		cert->setLastCrl(crl->getDate());
		certs->updatePKI(cert);
		CERR( "CRL done, completely");
		delete(crl);
	 	CERR("crl deleted");
	}
	catch (errorEx &err) {
		Error(err);
	}
}


void MainWindow::startRenameCert()
{
	try {
#ifdef qt3
		pki_base *pki = certs->getSelectedPKI();
		if (!pki) return;
		QListViewItem *item = (QListViewItem *)pki->getPointer();
		item->startRename(0);
#else
		renamePKI(certs);
#endif
	}
	catch (errorEx &err) {
		Error(err);
	}
}
