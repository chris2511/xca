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
		e + "'\nund wurde daher nicht importiert").data(), "OK");
		return;
	}
	pki_x509req *oldreq = (pki_x509req *)reqs->findPKI((pki_x509req *)req);
	if (oldreq) {
	   QMessageBox::information(this,"Zertifikatsanfragen import",
		("Die Zertifikatsanfrage ist bereits vorhanden als:\n'" +
		oldreq->getDescription() + 
		"'\nund wurde daher nicht erstellt").data(), "OK");
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
	dlg->descr->setText(req->getDescription().data());
	if ( req->verify() ) {
	      	dlg->verify->setDisabled(true);
		dlg->verify->setText("FEHLER");
	}
	/*if (pkey) {
	   pki_key *key = new pki_key(pkey);
	   if (key);
		dlg->keyPubEx->setText(key->pubEx());   
		dlg->keyModulus->setText(key->modulus());   
	   pki_key *existkey = keys->findPublicKey(key);
	   QColor *green = new QColor(0,192,0);
	   if (existkey) {
	        if (!existkey->onlyPubKey) {
	       	   dlg->privKey->setEnabled(true);
		   dlg->privKey->setText(existkey->getDescription());
	        }	
	   }
	}*/
	
	dlg->dnCN->setText(req->getDN(NID_commonName).data() );
	dlg->dnC->setText((req->getDN(
		NID_countryName) + " / " + 
		req->getDN(NID_stateOrProvinceName)).data());
	dlg->dnL->setText(req->getDN(NID_localityName).data());
	dlg->dnO->setText(req->getDN(NID_organizationName).data());
	dlg->dnOU->setText(req->getDN(NID_organizationalUnitName).data());
	dlg->dnEmail->setText(req->getDN(NID_pkcs9_emailAddress).data());
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
			"'\nwirklich löschen ?\n").data(),
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
			"'\nkonnte nicht geladen werden:\n" + errtxt).data());
		return;
	}
	pki_x509req *oldreq = (pki_x509req *)reqs->findPKI(req);
	if (oldreq) {
	   QMessageBox::information(this,"Zertifikatsanfragen import",
		("Die Zertifikatsanfrage ist bereits vorhanden als:\n'" +
		oldreq->getDescription() + 
		"'\nund wurde daher nicht importiert").data(), "OK");
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
			"'\nkonnte nicht gespeichert werden:\n" + errtxt).data());
		return;
	   }
	}
}

