#include "MainWindow.h"




MainWindow::MainWindow(QWidget *parent, const char *name) 
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
		   cerr << "Couldnt create: " << baseDir.latin1() << "\n";
	}
	dbfile = baseDir +  "/xca.db";
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	settings = new db_base(dbenv, dbfile.latin1(), "settings");
	initPass();
	keys = new db_key(dbenv, dbfile.latin1(), keyList);
	reqs = new db_x509req(dbenv, dbfile.latin1(), reqList, keys);
	certs = new db_x509(dbenv, dbfile.latin1(), certList, keys);
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


void MainWindow::initPass()
{
	PASS_INFO p;
	string passHash = settings->getString("pwhash");
	if (passHash == "") {
		string title="Neues Datenbank Passwort";
		string description="Bitte geben sie ein Passwort an mit dem Sie die Datenbank schützen wollen";
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
	     while (md5passwd() != passHash) {
		string title="Datenbank Passwort";
		string description="Bitte geben sie das Passwort für die Datenbank an";
		p.title = &title;
		p.description = &description;
		int keylen = passRead(pki_key::passwd, 25, 0, &p);
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
		dlg->title->setText(p->title->c_str());
		dlg->description->setText(p->description->c_str());
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
		dlg->title->setText(p->title->c_str());
		dlg->description->setText(p->description->c_str());
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
	cerr <<pki_key::passwd << "  "<< str << endl;
	return str;
}

