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


void MainWindow::newCert(pki_temp *templ)
{
	pki_x509 *cert = NULL;
	pki_x509 *signcert = NULL;
	pki_x509req *req = NULL;
	pki_key *signkey = NULL, *clientkey = NULL;
	int serial = 42; // :-)
	bool tempReq;
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
				 "sslCA", "emailCA", "objsignCA" };
	QListBoxItem *item;
	NewX509 *dlg = new NewX509(this, NULL, keys, reqs, certs, temps, certImg, nsImg );
	if (templ) {
		dlg->defineTemplate(templ);
	}
	dlg->setCert();
	if (!dlg->exec()) goto err;
	

	
	// Step 1 - Subject and key
	if (dlg->fromDataRB->isChecked()) {
	    clientkey = (pki_key *)keys->getSelectedPKI(dlg->keyList->currentText().latin1());
	    if (opensslError(clientkey)) goto err;
	    string cn = dlg->commonName->text().latin1();
	    string c = dlg->countryName->text().latin1();
	    string l = dlg->localityName->text().latin1();
	    string st = dlg->stateOrProvinceName->text().latin1();
	    string o = dlg->organisationName->text().latin1();
	    string ou = dlg->organisationalUnitName->text().latin1();
	    string email = dlg->emailAddress->text().latin1();
	    string desc = dlg->description->text().latin1();
	    req = new pki_x509req(clientkey, cn,c,l,st,o,ou,email,desc,"");
	    tempReq = true;
	    if (opensslError(req)) goto err;
	}
	else {
	    // A PKCS#10 Request was selected 
	    req = (pki_x509req *)reqs->getSelectedPKI(dlg->reqList->currentText().latin1());
	    if (opensslError(req)) goto err;
	    //clientkey = req->getKey();
	}
		
	// Step 2 - select Signing
	if (dlg->foreignSignRB->isChecked()) {
		signcert = (pki_x509 *)certs->getSelectedPKI(dlg->certList->currentText().latin1());
		if (opensslError(signcert)) goto err;
		signkey = signcert->getKey();
		if (opensslError(signkey)) goto err;
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
		certs->updatePKI(signcert);  // not so pretty ....
		CERR << "serial is: " << serial <<endl;
	}	
	
	// initially create cert 
	cert = new pki_x509(req->getDescription(), clientkey, req, signcert, x, serial);
	if (opensslError(cert)) goto err;
	
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
		CERR << subkey <<endl;
	}
	// Authority Key identifier
	if (dlg->authKey->isChecked()) {
		string authkey="keyid,issuer:always";
		cert->addV3ext(NID_authority_key_identifier, authkey);
		CERR << authkey <<endl;
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
		CERR << "KeyUsage:" <<keyuse1<< endl;
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
		CERR << "Extended Key Usage:" <<keyuse1<< endl;
	}
	
	
	// STEP 4
	// Subject Alternative name
	cont = "";
	cont = dlg->subAltName->text().latin1();
	if (dlg->subAltCp->isChecked()) {
		subAltName = "email:copy";
	}
	if (cont.length() > 0){
		addStr(subAltName,cont.c_str());
	}
	if (subAltName.length() > 0) {
		CERR << "SubAltName:" << subAltName<< endl;
		cert->addV3ext(NID_subject_alt_name, subAltName);
	}
	
	cont = "";
	cont = dlg->issAltName->text().latin1();
	// issuer alternative name	
	if (dlg->issAltCp->isChecked()) {
		issAltName = "issuer:copy";
	}
	if (cont.length() > 0){
		addStr(issAltName,cont.c_str());
	}
	if (issAltName.length() > 0) {
		CERR << "IssAltName:" << issAltName<< endl;
		cert->addV3ext(NID_issuer_alt_name, issAltName);
	}
		
	if (opensslError(cert)) goto err;
	// Step 5
	// Nestcape extensions 
	for (i=0; (item = dlg->nsCertType->item(i)); i++) {	
		if (item->selected()){
			addStr(certTypeStr, certTypeList[i]);
		}
	}
	CERR << "IssAltName:" << issAltName<< endl;
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
	if (opensslError(cert)) goto err;
	CERR << "SIGNED" <<endl;
	insertCert(cert);
	if (tempReq) delete(req);
	delete (dlg);
	return;
err:	
	if (cert) delete(cert);
	if (tempReq && req) delete(req);
	delete (dlg);
	return;

	
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
	CertDetail_UI *dlg = new CertDetail_UI(this,0,true);
	dlg->image->setPixmap(*certImg);
	dlg->descr->setText(cert->getDescription().c_str());

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
	CERR << cert->getEffTrust() <<endl;
	
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
	if ( !dlg->exec()) return false;
	string ndesc = dlg->descr->text().latin1();
	if (ndesc != cert->getDescription()) {
		certs->renamePKI(cert, ndesc);
	}
	if (opensslError(cert)) return false;
	return true;
}

void MainWindow::deleteCert()
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	if (opensslError(cert)) return;
	if (QMessageBox::information(this,tr("Delete Certificate"),
			tr("Really want to delete the Certificate") +":\n'" + 
			QString::fromLatin1(cert->getDescription().c_str()) +
			"'\n" ,
			tr("Delete"), tr("Cancel") )
	) return;
	certs->deletePKI(cert);
}

void MainWindow::loadCert()
{
	QStringList filt;
	filt.append(tr("Certificates ( *.pem *.der *.crt *.cer)")); 
	filt.append(tr("PKCS#12 Certificates ( *.p12 )")); 
	//filt.append(tr("PKCS#7 Signatures ( *.p7s )")); 
	filt.append(tr("All files ( *.* )"));
	QString s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate import"));
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile();
	if (s == "") return;
	s=QDir::convertSeparators(s);
	pki_x509 *cert = new pki_x509(s.latin1());
	if (opensslError(cert)) return;
	insertCert(cert);
}

void MainWindow::loadPKCS12()
{
	pki_pkcs12 *pk12;
	pki_x509 *acert;
	pki_key *akey;
	QStringList filt;
	filt.append(tr("PKCS#12 Certificates ( *.p12 )")); 
	filt.append(tr("All files ( *.* )"));
	QString s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate import"));
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile();
	if (s == "") return;
	s=QDir::convertSeparators(s);
	pk12 = new pki_pkcs12(s.latin1(), &MainWindow::passRead);
	opensslError(pk12);
	akey = pk12->getKey();
	acert = pk12->getCert();
	opensslError(akey);
	opensslError(acert);
	opensslError(pk12);
	insertKey(akey);
	insertCert(acert);
	for (int i=0; i<pk12->numCa(); i++) {
		acert = pk12->getCa(i);
		insertCert(acert);
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
	pki_x509 *oldcert = (pki_x509 *)certs->findPKI(cert);
	if (oldcert) {
	   QMessageBox::information(this,tr("Certificate import"),
		tr("The certificate already exists in the database as") +":\n'" +
		QString::fromLatin1(oldcert->getDescription().c_str()) + 
		"'\n" + tr("and so it was not imported"), "OK");
	   delete(cert);
	   return;
	}
	certs->insertPKI(cert);
}

void MainWindow::writeCert()
{
	QStringList filt;
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	filt.append(tr("Certificates ( *.pem *.der *.crt *.cer )")); 
	filt.append(tr("All Files ( *.* )"));
	QString s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate export"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::AnyFile );
	if (dlg->exec())
		s = dlg->selectedFile();
	if (s == "") return;
	s=QDir::convertSeparators(s);
	cert->writeCert(s.latin1(),true);
	opensslError(cert);
}


void MainWindow::writePKCS12()
{
	QStringList filt;
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	pki_key *privkey = (pki_key *)keys->findPKI(cert->getKey());
	if (privkey->isPubKey()) return; /* should not happen */
	filt.append(tr("PKCS#12 bags ( *.p12 *.pfx )")); 
	filt.append(tr("All Files ( *.* )"));
	QString s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("PKCS#12 export"));
	dlg->setFilters(filt);
	dlg->setMode( QFileDialog::AnyFile );
	if (dlg->exec())
		s = dlg->selectedFile();
	if (s == "") return;
	S=QDir::convertSeparators(s);
	pki_pkcs12 *p12 = new pki_pkcs12(cert->getDescription(), cert, privkey, &MainWindow::passWrite);
	pki_x509 *signer = cert->getSigner();
	int cnt =0;
	while ((signer != NULL ) && (signer != cert)) {
		p12->addCaCert(signer);
		CERR << "signer: " << ++cnt << endl;
		cert=signer;
		signer=signer->getSigner();
	}
	CERR << "start writing" <<endl;
	p12->writePKCS12(s.latin1());
	opensslError(cert);
}

void MainWindow::showPopupCert(QListViewItem *item, const QPoint &pt, int x) {
	CERR << "hallo popup" << endl;
	QPopupMenu *menu = new QPopupMenu(this);
	int itemExtend, itemRevoke, itemTrust, itemSerial;
	bool canSign, parentCanSign;
	if (!item) {
		menu->insertItem(tr("New Certificate"), this, SLOT(newCert()));
		menu->insertItem(tr("Import"), this, SLOT(loadCert()));
	}
	else {
		pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI(item->text(0).latin1());
		menu->insertItem(tr("Rename"), this, SLOT(startRenameCert()));
		menu->insertItem(tr("Show Details"), this, SLOT(showDetailsCert()));
		menu->insertItem(tr("Export"), this, SLOT(writeCert()));
		menu->insertItem(tr("Delete"), this, SLOT(deleteCert()));
		itemTrust = menu->insertItem(tr("Trust"), this, SLOT(setTrust()));
		menu->insertSeparator();
		itemSerial = menu->insertItem(tr("CA serial"), this, SLOT(setSerial()));
		menu->insertSeparator();
		itemExtend = menu->insertItem(tr("Extend"));
		if (cert) {
			if (cert->isRevoked()) {
				itemRevoke = menu->insertItem(tr("Unrevoke"), this, SLOT(unRevoke()));
				menu->setItemEnabled(itemTrust, false);
			}
			else	
				itemRevoke = menu->insertItem(tr("Revoke"), this, SLOT(revoke()));
			parentCanSign = (cert->getSigner() && cert->getSigner()->canSign() && (cert->getSigner() != cert));
			canSign = cert->canSign();
		}
		menu->setItemEnabled(itemExtend, parentCanSign);
		menu->setItemEnabled(itemRevoke, parentCanSign);
		menu->setItemEnabled(itemSerial, canSign);

	}
	menu->exec(pt);
	return;
}

void MainWindow::renameCert(QListViewItem *item, int col, const QString &text)
{
	if (col != 0) return;
	pki_base *pki = certs->getSelectedPKI(item);
	string txt =  text.latin1();
	certs->renamePKI(pki, txt);
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
	if (!dlg->exec()) return;
	if (dlg->trust0->isChecked()) newstate = 0;
	if (dlg->trust1->isChecked()) newstate = 1;
	if (dlg->trust2->isChecked()) newstate = 2;
	if (newstate==state) return;
	cert->setTrust(newstate);
	certs->updatePKI(cert);
	certs->updateViewAll();
}

void MainWindow::revoke()
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	cert->setRevoked(true);
	certs->updatePKI(cert);
	certs->updateViewAll();
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
	int nserial = QInputDialog::getInteger (xca_title,
			tr("Please enter the new Serial for signing"),
			serial, serial, 2147483647, 1, &ok, this );
	if (ok && nserial > serial) {
		cert->setCaSerial(nserial);
		certs->updatePKI(cert);
	}
}


void MainWindow::startRenameCert()
{
#ifdef qt3
	pki_base *pki = certs->getSelectedPKI();
	if (!pki) return;
	QListViewItem *item = (QListViewItem *)pki->getPointer();
	item->startRename(0);
#else
	renamePKI(certs);
#endif
}
