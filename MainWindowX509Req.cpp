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
	string challenge = dlg->challenge->text().latin1();
	pki_x509req *req = new pki_x509req(key, cn,c,l,st,o,ou,email,desc, challenge);
	insertReq(req);
}


void MainWindow::showDetailsReq()
{
	pki_x509req *req = (pki_x509req *)reqs->getSelectedPKI();
	showDetailsReq(req);
}
void MainWindow::showDetailsReq(QListViewItem *item)
{
	string req = item->text(0).latin1();
	showDetailsReq((pki_x509req *)reqs->getSelectedPKI(req));
}


void MainWindow::showDetailsReq(pki_x509req *req)
{
	if (!req) return;
	if (opensslError(req)) return;
	ReqDetail_UI *dlg = new ReqDetail_UI(this,0,true);
	dlg->descr->setText(req->getDescription().c_str());
	if ( req->verify() != pki_base::VERIFY_OK ) {
	      	dlg->verify->setDisabled(true);
		dlg->verify->setText("FEHLER");
	}
	pki_key *key =(pki_key *)keys->findPKI(req->getKey());
	if (key)
	    if(key->isPrivKey()) {
		dlg->privKey->setText(key->getDescription().c_str());
		dlg->privKey->setDisabled(false);
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
	if (opensslError(req)) return;
	if (QMessageBox::information(this,tr("Delete Certificate signing request"),
			tr("Really want to delete the Certificate signing request") +":\n'" + 
			QString::fromLatin1(req->getDescription().c_str()) +
			"'\n", "Delete", "Cancel")
	) return;
	reqs->deletePKI(req);
}

void MainWindow::loadReq()
{
	QStringList filt;
	filt.append("PKCS#10 CSR ( *.pem *.der )"); 
	filt.append("All Files ( *.* )");
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(tr("Import Certificate signing request"));
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	pki_x509req *req = new pki_x509req(s);
	if (opensslError(req)) return;
	insertReq(req);
}

void MainWindow::writeReq()
{
	QStringList filt;
	filt.append("PKCS#10 CSR ( *.pem *.der )"); 
	filt.append("All Files ( *.* )");
	string s;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption("Export Certificate signing request");
	dlg->setFilters(filt);
	if (dlg->exec())
		s = dlg->selectedFile().latin1();
	if (s == "") return;
	pki_x509req *req = (pki_x509req *)reqs->getSelectedPKI();
	if (opensslError(req)) return;
	req->writeReq(s,true);
	if (opensslError(req)) return;
}

void MainWindow::insertReq(pki_x509req *req)
{
	if (opensslError(req)) return;
	pki_x509 *oldreq = (pki_x509 *)reqs->findPKI(req);
	if (oldreq) {
	   QMessageBox::information(this,tr("Certificate signing request"),
		tr("The certificate signing request already exists in the database as") +":\n'" +
		QString::fromLatin1(oldreq->getDescription().c_str()) + 
		"'\n" + tr("and thus was not stored"), "OK");
	   delete(req);
	   return;
	}
	reqs->insertPKI(req);
}
