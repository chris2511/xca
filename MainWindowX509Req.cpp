#include "MainWindow.h"


void MainWindow::newReq()
{
	NewX509Req_UI *dlg = new NewX509Req_UI(this,0,true,0);
	dlg->keyList->insertStringList(keys->getPrivateDesc());
	if (! dlg->exec()) return;
	RSAkey *key = keys->getSelectedKey(dlg->keyList->currentText());
	cerr << "HIIIIEEER\n";
	QString cn = dlg->commonName->text();
	QString c = dlg->countryName->text();
	QString l = dlg->localityName->text();
	QString st = dlg->stateOrProvinceName->text();
	QString o = dlg->organisationName->text();
	QString ou = dlg->organisationalUnitName->text();
	QString email = dlg->emailAddress->text();
	X509Req *req = new X509Req(key, cn.latin1(),c.latin1(),l.latin1(),st.latin1(),o.latin1(),ou.latin1(),email.latin1(), this);
	cerr << "HIIIIEEER\n";
	req->setDescription(dlg->description->text());
	reqs->insertReq(req);
}

void MainWindow::showDetailsReq()
{
	ReqDetail_UI *dlg = new ReqDetail_UI(this,0,true);
	dlg->exec();
}

void MainWindow::deleteReq()
{
	X509Req *req = reqs->getSelectedReq();
	reqs->deleteReq(req);
}

