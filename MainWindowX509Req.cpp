#include "MainWindow.h"


void MainWindow::newX509Req()
{
	NewX509Req_UI *dlg = new NewX509Req_UI(this,0,true,0);
	dlg->keyList->insertStringList(keys->getPrivateDesc());
	dlg->exec();
	RSAkey *key = keys->getSelectedKey(dlg->keyList->currentText());
	X509Req *req = new X509Req(key, this);
	cerr << "HIIIIEEER\n";
	QString cn = dlg->commonName->text();
	QString c = dlg->countryName->text();
	QString l = dlg->localityName->text();
	QString st = dlg->stateOrProvinceName->text();
	QString o = dlg->organisationName->text();
	QString ou = dlg->organisationalUnitName->text();
	QString email = dlg->emailAddress->text();
	req->setDN(cn.latin1(),c.latin1(),l.latin1(),st.latin1(),o.latin1(),ou.latin1(),email.latin1());
	req->sign(key);
	cerr << "HIIIIEEER\n";
}
