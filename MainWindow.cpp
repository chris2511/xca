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
	settings = new QAsciiDict<char>();
	loadSettings();
	initPass();
	keys = new db_key(dbenv, dbfile.latin1(), "keydb", keyList);
	reqs = new db_x509req(dbenv, dbfile.latin1(), "reqdb", reqList, keys);
	certs = new db_x509(dbenv, dbfile.latin1(), "certdb", certList, keys);
};


MainWindow::~MainWindow() 
{
	 ERR_free_strings();
	 EVP_cleanup();
	 delete(keys);
	 delete(reqs);
	 delete(certs);
}

void MainWindow::loadSettings()
{
	int x;
	Dbc *cursor;
	Db *data = new Db(dbenv, 0);
	Dbt *k = new Dbt();
	Dbt *d = new Dbt();
	char *a, *b;
	a = settarr;
	if ((x = data->open(dbfile.latin1(), "settings", DB_BTREE, DB_CREATE, 0600))) 
		data->err(x,"DB open");
	if ((x = data->cursor(NULL, &cursor, 0)))
		data->err(x,"DB new Cursor");
	cerr <<"laden" <<endl;
	while (!cursor->get(k, d, DB_NEXT)) {
		cerr << "in Whileload: "<< endl;
		if (x) data->err(x,"DB Error get");
		else {
			memcpy(a,(char *)k->get_data(),k->get_size());
			b=a+k->get_size();
			memcpy(b,(char *)d->get_data(),d->get_size());
			settings->insert(a,b);
			a=b+d->get_size();
		}
	}
	data->close(0);
	delete(d);
	delete(k);
	delete(data);
}

void MainWindow::saveSettings()
{
	int x;
	Dbc *cursor;
	Db *data = new Db(dbenv, 0);
	if ((x = data->open(dbfile.latin1(), "settings", DB_BTREE, DB_CREATE, 0600))) 
		data->err(x,"DB open");
	if ((x = data->cursor(NULL, &cursor, 0)))
		data->err(x,"DB new Cursor");
        QAsciiDictIterator<char> it(*settings);
        for ( ; it.current(); ++it ) {
		cerr << "in save: "<< it.current() << endl;
		Dbt k( (void *)it.currentKey(), strlen(it.currentKey()) +1 );
		Dbt d( (void *)it.current(), strlen(it.current()) +1 );
		cerr << it.currentKey() << " -- " << it.current() <<endl;
		int x = data->put(NULL, &k, &d, 0);
		if (x) data->err(x,"DB Error put");
	}
	data->close(0);
	delete(data);
}

void MainWindow::initPass()
{
	if (!settings->find("pwhash")) {
		int keylen = passWrite((char *)pki_key::passwd, 25, 0, NULL);
		if (keylen == 0) {
			qFatal("Ohne Passwort laeuft hier gaaarnix :-)");
		}
		pki_key::passwd[keylen]='\0';

		settings->insert( "pwhash", md5passwd().c_str() );
		settings->insert( "meier", "aaaa");
		settings->insert( "mueller", "bbbbb");
		saveSettings();
	}
	else {
	     while (strncmp(md5passwd().c_str(), settings->find("pwhash"), 100)) {
		int keylen = passRead(pki_key::passwd, 25, 0, NULL);
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
	PassRead_UI *dlg = new PassRead_UI(NULL, 0, true);
	if (dlg->exec()) {
	   QString x = dlg->pass->text();
	   strncpy(buf, x.latin1(), size);
	   return x.length();
	}
	else return 0;
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
	cerr << str << endl;
	return str;
}


int MainWindow::passWrite(char *buf, int size, int rwflag, void *userdata)
{
	PassWrite_UI *dlg = new PassWrite_UI(NULL, 0, true);
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


