#include "MainWindow.h"


void MainWindow::newCert()
{
	NewX509_UI *dlg = new NewX509_UI(this,0,true,0);
	dlg->keyList->insertStringList(keys->getPrivateDesc());
	if (! dlg->exec()) return;
	pki_key *key = (pki_key *)keys->getSelectedPKI(dlg->keyList->currentText().latin1());
	string cn = dlg->commonName->text().latin1();
	string c = dlg->countryName->text().latin1();
	string l = dlg->localityName->text().latin1();
	string st = dlg->stateOrProvinceName->text().latin1();
	string o = dlg->organisationName->text().latin1();
	string ou = dlg->organisationalUnitName->text().latin1();
	string email = dlg->emailAddress->text().latin1();
	string desc = dlg->description->text().latin1();
	string days = dlg->validNumber->text().latin1();
	int range = dlg->validRange->currentItem();
	int x = atoi(days.c_str());
	if (range == 1) x *= 30;
	if (range == 2) x *= 365;

	pki_x509 *cert = new pki_x509(key, cn,c,l,st,o,ou,email,desc,x);
	string e;
	if ((e = cert->getError()) != "") {
	   QMessageBox::information(this,"Zertifikatsanfrage erstellen",
		("Beim Erstellen der Anfrage trat folgender Fehler auf:\n'" +
		e + "'\nund wurde daher nicht importiert").c_str(), "OK");
		return;
	}
	pki_x509 *oldcert = (pki_x509 *)certs->findPKI((pki_x509 *)cert);
	if (oldcert) {
	   QMessageBox::information(this,"Zertifikatsanfrage erstellen",
		("Die Zertifikatsanfrage ist bereits vorhanden als:\n'" +
		oldcert->getDescription() + 
		"'\nund wurde daher nicht importiert").c_str(), "OK");
	   delete(oldcert);
	   return;
	}
	certs->insertPKI(cert);
}

void MainWindow::showDetailsCert()
{
	CertDetail_UI *dlg = new CertDetail_UI(this,0,true);
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	dlg->descr->setText(cert->getDescription().c_str());
	if ( cert->verify() == pki_base::VERIFY_ERROR) {
	      	dlg->verify->setDisabled(true);
		dlg->verify->setText("FEHLER");
	}
	
	if ( cert->verify() == pki_base::VERIFY_SELFSIGNED) {
		dlg->verify->setText("SELF SIGNED");
	}
	
	if ( cert->verify() == pki_base::VERIFY_TRUSTED) {
		dlg->verify->setText("TRUSTED");
	}
	
	if ( cert->verify() == pki_base::VERIFY_UNTRUSTED) {
		dlg->verify->setText("NOT TRUSTED");
	}
	
	else {
	  pki_key *key = cert->getKey();
	  if (key)
	  {
	   dlg->keyPubEx->setText(key->pubEx().c_str());   
	   dlg->keyModulus->setText(key->modulus().c_str());   
	   dlg->keySize->setText(key->length().c_str());   
	   pki_key *existkey = (pki_key *)keys->findPKI(key);
	   if (existkey) {
	        if (!existkey->isPubKey()) {
	       	   dlg->privKey->setEnabled(true);
		   dlg->privKey->setText(existkey->getDescription().c_str());
	        }	
	   }
	  }
	}
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
	
	
	if ( !dlg->exec()) return;
	string ndesc = dlg->descr->text().latin1();
	if (ndesc != cert->getDescription()) {
		certs->updatePKI(cert, ndesc);
	}
}

void MainWindow::deleteCert()
{
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (!cert) return;
	if (QMessageBox::information(this,"Zertifikat löschen",
			("Möchten Sie das Zertifikat: '" + 
			cert->getDescription() +
			"'\nwirklich löschen ?\n").c_str(),
			"Löschen", "Abbrechen")
	) return;
	certs->deletePKI(cert);
}

void MainWindow::loadCert()
{
	QStringList filt;
	filt.append( "Zertifikate ( *.pem *.der )"); 
	filt.append("Alle Dateien ( *.* )");
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption("Zertifikat importieren");
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	pki_x509 *cert = new pki_x509(s);
	string errtxt;
	if ((errtxt = cert->getError()) != "") {
		QMessageBox::warning(this,"Datei Fehler",
			("Das Zertifikat: '" + s +
			"'\nkonnte nicht geladen werden:\n" + errtxt).c_str());
		return;
	}
	pki_x509 *oldcert = (pki_x509 *)certs->findPKI(cert);
	if (oldcert) {
	   QMessageBox::information(this,"Zertifikats import",
		("Das Zertifikat ist bereits vorhanden als:\n'" +
		oldcert->getDescription() + 
		"'\nund wurde daher nicht importiert").c_str(), "OK");
	   delete(oldcert);
	   return;
	}
	certs->insertPKI(cert);
}

void MainWindow::writeCert()
{
	QStringList filt;
	filt.append( "Zertifikat ( *.pem *.der )"); 
	filt.append("Alle Dateien ( *.* )");
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption("Zertifikat exportieren");
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	pki_x509 *cert = (pki_x509 *)certs->getSelectedPKI();
	if (cert) {
	   cert->writeReq(s,true);
	   string errtxt;
	   if ((errtxt = cert->getError()) != "") {
		QMessageBox::warning(this,"Datei Fehler",
			("Das Zertifikat: '" + s +
			"'\nkonnte nicht gespeichert werden:\n" + errtxt).c_str());
		return;
	   }
	}
}
