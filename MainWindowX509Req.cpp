#include "MainWindow.h"


void MainWindow::newReq()
{
	NewX509Req_UI *dlg = new NewX509Req_UI(this,0,true,0);
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
	pki_x509req *req = new pki_x509req(key, cn,c,l,st,o,ou,email,desc);
	string e;
	if ((e = req->getError()) != "") {
	   QMessageBox::information(this,"Zertifikatsanfrage erstellen",
		("Beim Erstellen der Anfrage trat folgender Fehler auf:\n'" +
		e + "'\nund wurde daher nicht importiert").c_str(), "OK");
		return;
	}
	pki_x509req *oldreq = (pki_x509req *)reqs->findPKI((pki_x509req *)req);
	if (oldreq) {
	   QMessageBox::information(this,"Zertifikatsanfrage erstellen",
		("Die Zertifikatsanfrage ist bereits vorhanden als:\n'" +
		oldreq->getDescription() + 
		"'\nund wurde daher nicht importiert").c_str(), "OK");
	   delete(oldreq);
	   return;
	}
	reqs->insertPKI(req);
}

void MainWindow::showDetailsReq()
{
	ReqDetail_UI *dlg = new ReqDetail_UI(this,0,true);
	pki_x509req *req = (pki_x509req *)reqs->getSelectedPKI();
	if (!req) return;
	dlg->descr->setText(req->getDescription().c_str());
	if ( req->verify() != pki_base::VERIFY_OK ) {
	      	dlg->verify->setDisabled(true);
		dlg->verify->setText("FEHLER");
	}
	else {
	  pki_key *key = req->getKey();
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
	string land = req->getDN( NID_countryName) + " / " 
		+ req->getDN(NID_stateOrProvinceName);
	dlg->dnCN->setText(req->getDN(NID_commonName).c_str() );
	dlg->dnC->setText(land.c_str());
	dlg->dnL->setText(req->getDN(NID_localityName).c_str());
	dlg->dnO->setText(req->getDN(NID_organizationName).c_str());
	dlg->dnOU->setText(req->getDN(NID_organizationalUnitName).c_str());
	dlg->dnEmail->setText(req->getDN(NID_pkcs9_emailAddress).c_str());
	if ( !dlg->exec()) return;
	string ndesc = dlg->descr->text().latin1();
	if (ndesc != req->getDescription()) {
		reqs->updatePKI(req, ndesc);
	}
}

void MainWindow::deleteReq()
{
	pki_x509req *req = (pki_x509req *)reqs->getSelectedPKI();
	if (!req) return;
	if (QMessageBox::information(this,"Zertifikatsanfrage löschen",
			("Möchten Sie die Zertifikatsanfrage: '" + 
			req->getDescription() +
			"'\nwirklich löschen ?\n").c_str(),
			"Löschen", "Abbrechen")
	) return;
	reqs->deletePKI(req);
}

void MainWindow::loadReq()
{
	QStringList filt;
	filt.append( "Zertifikatsanfragen ( *.pem *.der )"); 
	filt.append("Alle Dateien ( *.* )");
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption("Anfrage importieren");
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	pki_x509req *req = new pki_x509req(s);
	string errtxt;
	if ((errtxt = req->getError()) != "") {
		QMessageBox::warning(this,"Datei Fehler",
			("Die Zertifikatsanfrage: '" + s +
			"'\nkonnte nicht geladen werden:\n" + errtxt).c_str());
		return;
	}
	pki_x509req *oldreq = (pki_x509req *)reqs->findPKI(req);
	if (oldreq) {
	   QMessageBox::information(this,"Zertifikatsanfragen import",
		("Die Zertifikatsanfrage ist bereits vorhanden als:\n'" +
		oldreq->getDescription() + 
		"'\nund wurde daher nicht importiert").c_str(), "OK");
	   delete(oldreq);
	   return;
	}
	reqs->insertPKI(req);
}

void MainWindow::writeReq()
{
	QStringList filt;
	filt.append( "Zertifikatsanfragen ( *.pem *.der )"); 
	filt.append("Alle Dateien ( *.* )");
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption("Anfrage exportieren");
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	pki_x509req *req = (pki_x509req *)reqs->getSelectedPKI();
	if (req) {
	   req->writeReq(s,true);
	   string errtxt;
	   if ((errtxt = req->getError()) != "") {
		QMessageBox::warning(this,"Datei Fehler",
			("Die Zertifikatsanfrage: '" + s +
			"'\nkonnte nicht gespeichert werden:\n" + errtxt).c_str());
		return;
	   }
	}
}

