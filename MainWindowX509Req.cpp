#include "MainWindow.h"


void MainWindow::newReq()
{
	NewX509Req_UI *dlg = new NewX509Req_UI(this,0,true,0);
	dlg->keyList->insertStringList(keys->getPrivateDesc());
	if (! dlg->exec()) return;
	RSAkey *key = keys->getSelectedKey(dlg->keyList->currentText());
	QString cn = dlg->commonName->text();
	QString c = dlg->countryName->text();
	QString l = dlg->localityName->text();
	QString st = dlg->stateOrProvinceName->text();
	QString o = dlg->organisationName->text();
	QString ou = dlg->organisationalUnitName->text();
	QString email = dlg->emailAddress->text();
	X509Req *req = new X509Req(key, cn.latin1(),c.latin1(),l.latin1(),st.latin1(),o.latin1(),ou.latin1(),email.latin1(), this);
	QString e;
	if ((e = req->getError()) != NULL) {
	   QMessageBox::information(this,"Zertifikatsanfrage erstellen",
		"Beim Erstellen der Anfrage trat folgender Fehler auf:\n'" +
		e + "'\nund wurde daher nicht importiert", "OK");
		return;
	}
	X509Req *oldreq = reqs->findReq(req);
	if (oldreq) {
	   QMessageBox::information(this,"Zertifikatsanfragen import",
		"Die Zertifikatsanfrage ist bereits vorhanden als:\n'" +
		oldreq->description() + 
		"'\nund wurde daher nicht erstellt", "OK");
	   delete(oldreq);
	   return;
	}
	req->setDescription(dlg->description->text());
	reqs->insertReq(req);
}

void MainWindow::showDetailsReq()
{
	ReqDetail_UI *dlg = new ReqDetail_UI(this,0,true);
	X509Req *req = reqs->getSelectedReq();
	if (!req) return;
	dlg->descr->setText(req->description());
	EVP_PKEY *pkey = X509_REQ_get_pubkey(req->request);
	if ( X509_REQ_verify(req->request,pkey) <= 0) {
	      	dlg->verify->setDisabled(true);
		dlg->verify->setText("FEHLER");
	}
	if (pkey) {
	   RSAkey *key = new RSAkey(pkey);
	   if (key);
		dlg->keyPubEx->setText(key->pubEx());   
		dlg->keyModulus->setText(key->modulus());   
	   RSAkey *existkey = keys->findPublicKey(key);
	   QColor *green = new QColor(0,192,0);
	   if (existkey) {
	        if (!existkey->onlyPubKey) {
	       	   dlg->privKey->setEnabled(true);
		   dlg->privKey->setText(existkey->description());
	        }	
	   }
	}
	QStringList *l = req->getDN();
	QStringList::Iterator it = l->begin();
	
	dlg->dnCN->setText(*it);
	dlg->dnC->setText(*++it + " / " + *++it);
	dlg->dnL->setText(*++it);
	dlg->dnO->setText(*++it);
	dlg->dnOU->setText(*++it);
	dlg->dnEmail->setText(*++it);
	if ( !dlg->exec()) return;
	QString ndesc = dlg->descr->text();
	if (ndesc != req->description()) {
		reqs->updateReq(req, ndesc);
	}
}

void MainWindow::deleteReq()
{
	X509Req *req = reqs->getSelectedReq();
	if (!req) return;
	if (QMessageBox::information(this,"Zertifikatsanfrage löschen",
			"Möchten Sie die Zertifikatsanfrage: '" + 
			req->description() +
			"'\nwirklich löschen ?\n",
			"Löschen", "Abbrechen")
	) return;
	reqs->deleteReq(req);
}

void MainWindow::loadReq()
{
	QStringList filt;
	filt.append( "Zertifikatsanfragen ( *.pem *.der )"); 
	filt.append("Alle Dateien ( *.* )");
	QString s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption("Anfrage importieren");
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile();
	if (s.isEmpty()) return;
	X509Req *req = new X509Req(s);
	QString errtxt;
	if ((errtxt = req->getError()) != NULL) {
		QMessageBox::warning(this,"Datei Fehler",
			"Die Zertifikatsanfrage: '" + s +
			"'\nkonnte nicht geladen werden:\n" + errtxt);
		return;
	}
	X509Req *oldreq = reqs->findReq(req);
	if (oldreq) {
	   QMessageBox::information(this,"Zertifikatsanfragen import",
		"Die Zertifikatsanfrage ist bereits vorhanden als:\n'" +
		oldreq->description() + 
		"'\nund wurde daher nicht importiert", "OK");
	   delete(oldreq);
	   return;
	}
	reqs->insertReq(req);
}

void MainWindow::writeReq()
{
	QStringList filt;
	filt.append( "Zertifikatsanfragen ( *.pem *.der )"); 
	filt.append("Alle Dateien ( *.* )");
	QString s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption("Anfrage exportieren");
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile();
	if (s.isEmpty()) return;
	X509Req *req = reqs->getSelectedReq();
	if (req) {
	   req->writeReq(s,true);
	   QString errtxt;
	   if ((errtxt = req->getError()) != NULL) {
		QMessageBox::warning(this,"Datei Fehler",
			"Die Zertifikatsanfrage: '" + s +
			"'\nkonnte nicht gespeichert werden:\n" + errtxt);
		return;
	   }
	}
}

