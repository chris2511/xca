#include "MainWindow.h"


void MainWindow::newCert()
{
	pki_x509 *cert = NULL;
	pki_x509 *signcert = NULL;
	pki_x509req *req = NULL;
	pki_key *signkey = NULL, *key = NULL;
	int serial = 42; // :-)
	
	// Step 1 - Subject and key
	NewX509 *dlg1 = new NewX509(this, NULL, keys, reqs);
	if (! dlg1->exec()) return;
	if (dlg1->fromDataRB->isChecked()) {
	    key = (pki_key *)keys->getSelectedPKI(dlg1->keyList->currentText().latin1());
	    if (opensslError(key)) return;
	    string cn = dlg1->commonName->text().latin1();
	    string c = dlg1->countryName->text().latin1();
	    string l = dlg1->localityName->text().latin1();
	    string st = dlg1->stateOrProvinceName->text().latin1();
	    string o = dlg1->organisationName->text().latin1();
	    string ou = dlg1->organisationalUnitName->text().latin1();
	    string email = dlg1->emailAddress->text().latin1();
	    string desc = dlg1->description->text().latin1();
	    req = new pki_x509req(key, cn,c,l,st,o,ou,email,desc,"");
	    if (opensslError(req)) return;
	}
	else {
	    // A PKCS#10 Request was selected 
	    req = (pki_x509req *)reqs->getSelectedPKI(dlg1->reqList->currentText().latin1());
	    if (opensslError(req)) return;
	}
		
	// Step 2 - select Signing
	NewX509_1_UI *dlg2 = new NewX509_1_UI(this, NULL, true ,0);
	QStringList strlist = certs->getPrivateDesc();
	if (strlist.isEmpty()) {
		dlg2->foreignSignRB->setDisabled(true);
		dlg2->certList->setDisabled(true);
	}
	else {
		dlg2->certList->insertStringList(strlist);
	}
	if (dlg1->fromDataRB->isChecked())
		// if we entered subjectdata, selfsigning is default
		dlg2->selfSignRB->setChecked(true);
	else 
		// for PKCS#10 signing foreignKey signing is default
		dlg2->foreignSignRB->setChecked(true);
	if (!dlg2->exec()) return;
	if (dlg2->foreignSignRB->isChecked()) {
		signcert = (pki_x509 *)certs->getSelectedPKI(dlg2->certList->currentText().latin1());
		if (opensslError(signcert)) return;
		signkey = certs->findKey(signcert);
		if (opensslError(signkey)) return;
		// search for serial in database
		string serhash = signcert->fingerprint(EVP_md5()) + "serial";
		serial = settings->getInt(serhash) + 1;
		CERR << "serial is: " << serial <<endl;
		settings->putInt(serhash, serial);
		
	}
	else {
		signkey = key;	
		bool ok;
		serial = dlg2->serialNr->text().toInt(&ok);
		if (!ok) serial = 0;
	}
	
	
	// Step 3 - Choose the Date and all the V3 extensions
	NewX509_2_UI *dlg3 = new NewX509_2_UI(this, NULL, true ,0);
	if (! dlg3->exec()) return;
	
	// Date handling
	int x = dlg3->validNumber->text().toInt();
	int days = dlg3->validRange->currentItem();
	if (days == 1) x *= 30;
	if (days == 2) x *= 365;
	
	cert = new pki_x509(req->getDescription(), req, signcert, x, serial);
	if (opensslError(cert)) return;
	
	// handle extensions
	// basic constraints
	string constraints;
	if (dlg3->bcCritical->isChecked()) constraints = "critical,";
	constraints +="CA:";
	constraints += dlg3->basicCA->currentText().latin1();
	string pathstr = dlg3->basicPath->text().latin1();
	if (pathstr.length()>0) {
		constraints += ", pathlen:";
		constraints += pathstr;
	}
	cert->addV3ext(NID_basic_constraints, constraints);
	CERR << "B-Const:" << constraints << endl;
	// Subject Key identifier
	if (dlg3->subKey->isChecked()) {
		string subkey="hash";
		cert->addV3ext(NID_subject_key_identifier, subkey);
		CERR << subkey <<endl;
	}
	// Authority Key identifier
	if (dlg3->authKey->isChecked()) {
		string authkey="keyid,issuer:always";
		cert->addV3ext(NID_authority_key_identifier, authkey);
		CERR << authkey <<endl;
	}
	
	// key usage
	char *keyusage[] ={"digitalSignature", "nonRepudiation", "keyEncipherment",
		"dataEncipherment", "keyAgreement", "keyCertSign",
		"cRLSign", "encipherOnly", "decipherOnly"};
	QListBoxItem *item;
	int i=0;
	string keyuse, keyuse1;
	while ((item = dlg3->keyUsage->item(i))) {	
		if (item->selected()){
			if (keyuse.length() > 0) keyuse +=", ";
			keyuse += keyusage[i];
		}
		i++;
	}
	
	if (keyuse.length() > 0) {
		if (dlg3->kuCritical->isChecked()) keyuse1 = "critical, " +keyuse;
		cert->addV3ext(NID_key_usage, keyuse1);
		CERR << "KeyUsage:" <<keyuse1<< endl;
	}
	if (opensslError(cert)) return;
	// and finally sign the request 
	cert->sign(signkey);
	if (opensslError(cert)) return;
	CERR << "SIGNED" <<endl;
	insertCert(cert);
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


void MainWindow::showDetailsCert(pki_x509 *cert)
{
	if (!cert) return;
	if (opensslError(cert)) return;
	CertDetail_UI *dlg = new CertDetail_UI(this,0,true);
	dlg->descr->setText(cert->getDescription().c_str());
	// examine the key
	pki_key *key= (pki_key *)keys->findPKI(cert->getKey());
	if (key)
	     if (key->isPrivKey()) {
		dlg->privKey->setText(key->getDescription().c_str());
	      	dlg->privKey->setDisabled(false);
	     }								

	// examine the signature
	if ( cert->getSigner() == NULL) {
		dlg->verify->setText(tr("NOT TRUSTED"));
	      	dlg->verify->setDisabled(true);
	}
	else if ( cert->compare(cert->getSigner()) ) {
		dlg->verify->setText(tr("SELF SIGNED"));
	}
	
	else {
		dlg->verify->setText(cert->getSigner()->getDescription().c_str());
	}
	
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
	if (cert->checkDate() == -1) {
		dlg->dateValid->setText(tr("Not valid"));
	      	dlg->dateValid->setDisabled(true);
	}
	if (cert->checkDate() == +1) {
		dlg->dateValid->setText(tr("Not valid"));
	      	dlg->dateValid->setDisabled(true);
	}
	
	// the fingerprints
	dlg->fpMD5->setText(cert->fingerprint(EVP_md5()).c_str());
	dlg->fpSHA1->setText(cert->fingerprint(EVP_sha1()).c_str());
	
	// V3 extensions
	dlg->v3Extensions->setText(cert->printV3ext().c_str());

	// show it to the user...	
	if ( !dlg->exec()) return;
	string ndesc = dlg->descr->text().latin1();
	if (ndesc != cert->getDescription()) {
		certs->updatePKI(cert, ndesc);
	}
	opensslError(cert);
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
	filt.append(tr("PKCS#7 Signatures ( *.p7s )")); 
	filt.append(tr("All files ( *.* )"));
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate import"));
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	pki_x509 *cert = new pki_x509(s);
	if (opensslError(cert)) return;
	insertCert(cert);
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
	filt.append(tr("Certificates ( *.pem *.der *.crt *.cer )")); 
	filt.append(tr("All Files ( *.* )"));
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Certificate export"));
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (cert) {
	   cert->writeCert(s,true);
	   opensslError(cert);
	}
}


void MainWindow::writePKCS12()
{
	QStringList filt;
	filt.append(tr("PKCS#12 bags ( *.p12 *.pfx )")); 
	filt.append(tr("All Files ( *.* )"));
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("PKCS#12 export"));
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (cert) {
	   pki_key *privkey = (pki_key *)keys->findPKI(cert->getKey());
	   if (privkey->isPubKey()) return; /* should not happen */
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
	   p12->writePKCS12(s);

	   opensslError(cert);
	}
}

