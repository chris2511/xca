#include "NewX509.h"

NewX509::NewX509(QWidget *parent , const char *name, db_key *key, db_x509req *req)
	:NewX509_UI(parent, name, true, 0)
{
	connect( this, SIGNAL(genKey()), parent, SLOT(newKey()) );
	keys = key;
	reqs = req;
	QStringList strings = keys->getPrivateDesc();
	// are there any private keys to use ?
	if (strings.isEmpty()) {
		newKey();
	}
	else {
		keyList->insertStringList(strings);
	}
	// any PKCS#10 requests to be used ?
	strings = reqs->getDesc();
	if (strings.isEmpty()) {
		fromReqRB->setDisabled(true);
	}
	else {
		reqList->insertStringList(strings);
	}
	fromDataRB->setChecked(true);
}
	
void NewX509::setDisabled(int state)
{
   if (state == 2) {
	inputFrame->setDisabled(false);
	reqList->setDisabled(true);
   }
   else if (state == 0) {
	inputFrame->setDisabled(true);
	reqList->setDisabled(false);
   }
}

void NewX509::newKey()
{
	emit genKey();
	keyList->clear();
	keyList->insertStringList(keys->getPrivateDesc());
}

void NewX509::validateFields() {
	QStringList fields;
	if (fromReqRB->isChecked()) {
		accept();
		return;
	}
	
	if (description->text() == "") 
		fields.append(tr("Description"));
	if (commonName->text() == "") 
		fields.append(tr("Common Name"));
	if (emailAddress->text() == "") 
		fields.append(tr("Email Address"));

	if (!fields.isEmpty()) {
		 QMessageBox::information(this,tr("Missing parameter"),
				 tr("The following fields must not be empty") +":\n'"+
				 fields.join("'\n'") + "'", "OK"); 
	}
	else {
		accept();
	}
}

