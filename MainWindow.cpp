#include "MainWindow.h"




MainWindow::MainWindow(QWidget *parent, const char *name) 
	:MainWindow_UI(parent, name)
{
	connect(quitApp, SIGNAL(clicked()), qApp, SLOT(quit()) );
	baseDir = QDir::homeDirPath() + BASE_DIR;
 	dbenv = new DbEnv(DB_CXX_NO_EXCEPTIONS | DB_INIT_TXN);
	QDir d(baseDir);
	if ( ! d.exists() ){
		if (!d.mkdir(baseDir)) 
		   cerr << "Couldnt create: " << baseDir.latin1() << "\n";
	}
	QString dbfile = baseDir +  "/xca.db";
	keys = new db_key(dbenv, dbfile.latin1(), "keydb", keyList);
	reqs = new db_x509req(dbenv, dbfile.latin1(), "reqdb", reqList);
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();


};


MainWindow::~MainWindow() 
{
	 ERR_free_strings();
	 EVP_cleanup();
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


