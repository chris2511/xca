#include "MainWindow.h"




MainWindow::MainWindow(QWidget *parent, const char *name ) 
	:MainWindow_UI(parent, name)
{
	connect((QObject *) quitApp, SIGNAL(clicked()), (QObject *)qApp, SLOT(quit()) );
	QString cpr = "(c) 2002 by Christian@Hohnstaedt.de - Version: ";
	copyright->setText(cpr + VER);
	baseDir = QDir::homeDirPath() + BASE_DIR;
 	dbenv = new DbEnv(DB_CXX_NO_EXCEPTIONS | DB_INIT_TXN );
	QDir d(baseDir);
	if ( ! d.exists() ){
		if (!d.mkdir(baseDir)) 
		   qFatal(  "Couldnt create: " +  baseDir );
	}
	if (qApp->argc() <2){
		dbfile="xca.db";
	}
	else {
		dbfile=qApp->argv()[1];
	}
	dbfile = baseDir + "/" +  dbfile;
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	settings = new db_base(dbenv, dbfile.latin1(), "settings");
	initPass();
	keys = new db_key(dbenv, dbfile.latin1(), keyList);
	reqs = new db_x509req(dbenv, dbfile.latin1(), reqList, keys);
	certs = new db_x509(dbenv, dbfile.latin1(), certList, keys);
	keyImg = loadImg("bigkey.png");
	csrImg = loadImg("bigcsr.png");
	certImg = loadImg("bigcert.png");
	bigKey->setPixmap(*keyImg);
	bigCsr->setPixmap(*csrImg);
	bigCert->setPixmap(*certImg);
};


MainWindow::~MainWindow() 
{
	 ERR_free_strings();
	 EVP_cleanup();
	 delete(keys);
	 delete(reqs);
	 delete(certs);
	 delete(settings);
}


QPixmap *MainWindow::loadImg(const char *name )
{
        return settings->loadImg(name);
}			


void MainWindow::initPass()
{
	PASS_INFO p;
	string passHash = settings->getString("pwhash");
	if (passHash == "") {
		string title="New Database Password";
		string description="Please enter a password, that will be used to encrypt your private keys in the database-file";
		p.title = &title;
		p.description = &description;
		int keylen = passWrite((char *)pki_key::passwd, 25, 0, &p);
		if (keylen == 0) {
			qFatal("Ohne Passwort laeuft hier gaaarnix :-)");
		}
		pki_key::passwd[keylen]='\0';
		settings->putString( "pwhash", md5passwd() );
	}
	else {
	     int keylen=0;		
	     while (md5passwd() != passHash) {
		if (keylen !=0)
		  QMessageBox::warning(this,tr("Password"), tr("Password verify error, please try again"));	
		string title= "Database Password";
		string description="Please enter the password for unlocking the database";
		p.title = &title;
		p.description = &description;
		keylen = passRead(pki_key::passwd, 25, 0, &p);
		if (keylen == 0) {
			qFatal("Ohne Passwort laeuft hier gaaarnix :-)");
		}
		pki_key::passwd[keylen]='\0';
	    }
	}
}


// Static Password Callback functions 

int MainWindow::passRead(char *buf, int size, int rwflag, void *userdata)
{
	PASS_INFO *p = (PASS_INFO *)userdata;
	PassRead_UI *dlg = new PassRead_UI(NULL, 0, true);
	if (p != NULL) {
		dlg->title->setText(tr(p->title->c_str()));
		dlg->description->setText(tr(p->description->c_str()));
	}
	if (dlg->exec()) {
	   QString x = dlg->pass->text();
	   strncpy(buf, x.latin1(), size);
	   return x.length();
	}
	else return 0;
}


int MainWindow::passWrite(char *buf, int size, int rwflag, void *userdata)
{
	PASS_INFO *p = (PASS_INFO *)userdata;
	PassWrite_UI *dlg = new PassWrite_UI(NULL, 0, true);
	if (p != NULL) {
		dlg->title->setText(tr(p->title->c_str()));
		dlg->description->setText(tr(p->description->c_str()));
	}
	if (dlg->exec()) {
	   QString A = dlg->passA->text();
	   QString B = dlg->passB->text();
	   if (A != B) return 0;
	   strncpy(buf, A.latin1(), size);
	   return A.length();
	}
	else return 0;
}

void MainWindow::incProgress(int a, int b, void *progress)
{
	int i = ((QProgressDialog *)progress)->progress();
	((QProgressDialog *)progress)->setProgress(++i);
}

void MainWindow::renamePKI(db_base *db)
{
	pki_base * pki = db->getSelectedPKI();
	Rename_UI *dlg = new Rename_UI(this,0,true);
	dlg->newName->setText(pki->getDescription().c_str());
	if (dlg->exec()) {
		db->updatePKI(pki, dlg->newName->text().latin1());
	}
}


string MainWindow::md5passwd()
{

	EVP_MD_CTX mdctx;
	string str;
	unsigned int n;
	int j;
	char zs[4];
	unsigned char m[EVP_MAX_MD_SIZE];
	EVP_DigestInit(&mdctx, EVP_md5());
	EVP_DigestUpdate(&mdctx, pki_key::passwd, strlen(pki_key::passwd));
	EVP_DigestFinal(&mdctx, m, &n);
	for (j=0; j<(int)n; j++) {
		sprintf(zs, "%02X%c",m[j], (j+1 == (int)n) ?'\0':':');
		str += zs;
	}
	return str;
}

bool MainWindow::opensslError(pki_base *pki)
{
	string err;

	if (!pki) {
		QMessageBox::warning(this,tr("Internal Error"), tr("The system detected a NULL pointer, maybe the system is out of memory" ));
		qFatal("NULL pointer detected - Exiting");
	}
	
	if (( err = pki->getError()) != "") { 
		QMessageBox::warning(this,tr("OpenSSL Error"), tr("The openSSL library raised the following error")+":" +
			QString::fromLatin1(err.c_str()));
		return true;
	}
	return false;
}
	
	
