#include "NewX509.h"

NewX509::NewX509(QWidget *parent , const char *name, db_key *key, db_x509req *req)
	:NewX509_UI(parent, name, true, 0)
{
	connect( this, SIGNAL(genKey()), parent, SLOT(newKey()) );
	keys = key;
	reqs = req;
	par = (MainWindow *)parent;
	keyList->insertStringList(keys->getPrivateDesc());
	reqList->insertStringList(reqs->getDesc());
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

