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
	loadSettings();
	initPass();
	keys = new db_key(dbenv, dbfile.latin1(), "keydb", keyList, passwd);
	reqs = new db_x509req(dbenv, dbfile.latin1(), "reqdb", reqList);
	certs = new db_x509(dbenv, dbfile.latin1(), "certdb", certList);
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
	if ((x = data->open(dbfile.latin1(), "settings", DB_BTREE, DB_CREATE, 0600))) 
		data->err(x,"DB open");
	if ((x = data->cursor(NULL, &cursor, 0)))
		data->err(x,"DB new Cursor");
	cerr <<"laden" <<endl;
	while (!cursor->get(k, d, DB_NEXT)) {
		cerr << "in Whileload: "<< endl;
		if (x) data->err(x,"DB Error get");
		else {
			settings.insert((char *)k->get_data(), (char *)d->get_data());
		}
	}
	cerr <<"pwhash " << settings["pwhash"] <<endl;
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
        QAsciiDictIterator<char> it(settings);
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
	if (!settings["pwhash"]) {
		int keylen = passWrite(passwd, sizeof(passwd), 0, NULL);
		if (keylen == 0) {
			qFatal("Ohne Passwort laeuft hier gaaarnix :-)");
		}
		passwd[keylen]='\0';
		settings.insert( "pwhash", passwd );
		settings.insert( "meier", "aaaa");
		settings.insert( "mueller", "bbbbb");
		saveSettings();
	}
	else {
	    while (strncmp(passwd, settings["pwhash"], sizeof(passwd))) {
		int keylen = passRead(passwd, sizeof(passwd), 0, NULL);
		if (keylen == 0) {
			qFatal("Ohne Passwort laeuft hier gaaarnix :-)");
		}
		passwd[keylen]='\0';
		cerr << passwd << " - " << settings["pwhash"] << endl;
	    }
	}
}
	    // Static Password Callback functions

int MainWindow::passRead(char *buf, int size, int rwflag, void *userdata)
{
	PassRead_UI *dlg = new PassRead_UI(NULL, 0, true);
	if (dlg->exec()) {
	   QString x = dlg->pass->text();
	   const char *pass = x.latin1();
	   strncpy(buf, pass, size);
	   return x.length();
	}
	else return 0;
}


int MainWindow::passWrite(char *buf, int size, int rwflag, void *userdata)
{
	PassWrite_UI *dlg = new PassWrite_UI(NULL, 0, true);
	if (dlg->exec()) {
	   QString A = dlg->passA->text();
	   QString B = dlg->passB->text();
	   if (A != B) return 0;
	   const char *pass = A.latin1();
	   strncpy(buf, pass, size);
	   return A.length();
	}
	else return 0;
}

void MainWindow::incProgress(int a, int b, void *progress)
{
	int i = ((QProgressDialog *)progress)->progress();
	((QProgressDialog *)progress)->setProgress(++i);
}


