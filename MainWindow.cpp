/*
 * Copyright (C) 2001 Christian Hohnstaedt.
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  - Neither the name of the author nor the names of its contributors may be 
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * This program links to software with different licenses from:
 *
 *	http://www.openssl.org which includes cryptographic software
 * 	written by Eric Young (eay@cryptsoft.com)"
 *
 *	http://www.sleepycat.com
 *
 *	http://www.trolltech.com
 * 
 *
 *
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$ 
 *
 */                           


#include "MainWindow.h"

QPixmap *MainWindow::keyImg = NULL, *MainWindow::csrImg = NULL,
	*MainWindow::certImg = NULL, *MainWindow::tempImg = NULL,
	*MainWindow::nsImg = NULL, *MainWindow::revImg = NULL,
	*MainWindow::appIco = NULL;




MainWindow::MainWindow(QWidget *parent, const char *name ) 
	:MainWindow_UI(parent, name)
{
	connect( (QObject *)quitApp, SIGNAL(clicked()), (QObject *)qApp, SLOT(quit()) );
	QString cpr = "(c) 2002 by Christian@Hohnstaedt.de - Version: ";
	copyright->setText(cpr + VER);
	setCaption(tr(XCA_TITLE));
	dbfile="xca.db";
	keys = NULL;
	reqs = NULL;
	certs = NULL;
	temps = NULL;
	dbenv = NULL;
	global_tid = NULL;
#ifdef WIN32
	baseDir = "";
#else	
	baseDir = QDir::homeDirPath();
	baseDir += QDir::separator();

	baseDir += BASE_DIR;
	QDir d(baseDir);
        if ( ! d.exists() ){
		if (!d.mkdir(baseDir))
			qFatal(  "Couldnt create: " +  baseDir );
	}
	
#endif
	
#ifdef qt3	
	connect( keyList, SIGNAL(itemRenamed(QListViewItem *, int, const QString &)),
			this, SLOT(renameKey(QListViewItem *, int, const QString &)));
	connect( reqList, SIGNAL(itemRenamed(QListViewItem *, int, const QString &)),
			this, SLOT(renameReq(QListViewItem *, int, const QString &)));
	connect( certList, SIGNAL(itemRenamed(QListViewItem *, int, const QString &)),
			this, SLOT(renameCert(QListViewItem *, int, const QString &)));
	connect( tempList, SIGNAL(itemRenamed(QListViewItem *, int, const QString &)),
			this, SLOT(renameTemp(QListViewItem *, int, const QString &)));
#endif	
	MARK
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	init_images();
	MARK

	read_cmdline();
	if (exitApp) return;
	init_database();
}

void MainWindow::init_images(){
	
	keyImg = loadImg("bigkey.png");
	csrImg = loadImg("bigcsr.png");
	certImg = loadImg("bigcert.png");
	tempImg = loadImg("bigtemp.png");
	nsImg = loadImg("netscape.png");
	revImg = loadImg("bigcrl.png");
	appIco = loadImg("key.xpm");
	bigKey->setPixmap(*keyImg);
	bigCsr->setPixmap(*csrImg);
	bigCert->setPixmap(*certImg);
	bigTemp->setPixmap(*tempImg);
	bigRev->setPixmap(*revImg);
	setIcon(*appIco);
}		
	
void MainWindow::read_cmdline()
{
#define XCA_KEY 1
#define XCA_REQ 2
#define XCA_CERT 3
#define XCA_P12 5
#define XCA_DB 4

	int type = XCA_DB;
	int cnt = 1;
	char *arg = NULL;
	pki_key *key;
	pki_x509 *cert;
	pki_x509req *req;
	pki_pkcs12 *p12;
	exitApp = 0;
	
	while (cnt < qApp->argc()) {
		arg = qApp->argv()[cnt];
		if (arg[0] == '-') { // option
			switch (arg[1]) {
				case 'c' : type = XCA_CERT;
					   exitApp =1;
					   break;
				case 'r' : type = XCA_REQ;
					   exitApp =1;
					   break;
				case 'k' : type = XCA_KEY;
					   exitApp =1;
					   break;
				case 'p' : type = XCA_P12;
					   exitApp =1;
					   break;
				case 'd' : type = XCA_DB;
					   break;
				case 'v' : type = XCA_DB;
					   cout << tr(XCA_TITLE) << 
						   endl << VER << endl;
					   exitApp =1;
					   return;
					   break;
			}
			if (arg[2] != '\0') {
				 arg=&(arg[2]);
			}
			else {
				if (++cnt >= qApp->argc()) {
					qFatal("cmdline argument error\n");
				}
				arg=qApp->argv()[cnt];
			}
		}
		try {
		    switch (type) {
			case XCA_DB : dbfile = arg;
				     break;
			case XCA_KEY : 
		 		key = new pki_key(arg, &MainWindow::passRead);
				showDetailsKey(key, true);
				MARK
				break;
			case XCA_CERT : 
		 		cert = new pki_x509(arg);
				showDetailsCert(cert, true);
				break;
			case XCA_REQ : 
		 		req = new pki_x509req(arg);
				showDetailsReq(req, true);
				break;
			case XCA_P12 : 
		 		p12 = new pki_pkcs12(arg, &MainWindow::passRead);
				insertP12(p12);
				delete p12;
				break;
		    }
		}
		
		catch (errorEx &err) {
			Error(err);
		}
		
		cnt++;
	}
}	



void MainWindow::init_database() {
	
	if (dbenv) return; // already initialized....
	try {
		dbenv = new DbEnv(0);
		dbenv->set_errcall(&MainWindow::dberr);
		dbenv->open(baseDir.latin1(), DB_RECOVER | DB_INIT_TXN | \
				DB_INIT_MPOOL | DB_INIT_LOG | DB_INIT_LOCK | \
				DB_CREATE , 0600 );
		dbenv->txn_begin(NULL, &global_tid, 0);
#ifndef DB_AUTO_COMMIT
#define DB_AUTO_COMMIT 0
#endif
		dbenv->set_flags(DB_AUTO_COMMIT,1);
		MARK
	}
	catch (DbException &err) {
		DBEX(err);
		QString e = err.what();
		e += " (" + baseDir + ")";
		qFatal(e);
	}
	try {
		settings = new db_base(dbenv, dbfile.latin1(), "settings",global_tid);
		MARK
		initPass();
		keys = new db_key(dbenv, dbfile.latin1(), keyList,global_tid);
		reqs = new db_x509req(dbenv, dbfile.latin1(), reqList, keys,global_tid);
		certs = new db_x509(dbenv, dbfile.latin1(), certList, keys,global_tid);
		temps = new db_temp(dbenv, dbfile.latin1(), tempList,global_tid);
		crls = new db_crl(dbenv, dbfile.latin1(), revList, global_tid, certs);
	}
	catch (errorEx &err) {
		Error(err);
	}
	catch (DbException &err) {
		DBEX(err);
		qFatal(err.what());
	}
}		



MainWindow::~MainWindow() 
{
	ERR_free_strings();
	EVP_cleanup();
	if (dbenv) {
		delete(keys);
		delete(reqs);
		delete(certs);
		delete(temps);
		delete(settings);
		delete(crls);
		global_tid->commit(0);
		MARK
		dbenv->close(0);
		MARK
	}
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
		string title=tr("New Password").latin1();
		string description=tr("Please enter a password, that will be used to encrypt your private keys in the database-file").latin1();
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
			QMessageBox::warning(this,tr(XCA_TITLE), tr("Password verify error, please try again"));	
		string title=tr("Password").latin1();
		string description=tr("Please enter the password for unlocking the database").latin1();
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

void MainWindow::renamePKI(db_base *db)
{
        pki_base * pki = db->getSelectedPKI();
	if (!pki) return;
        QString name= pki->getDescription().c_str();
	bool ok;
	QString nname = QInputDialog::getText (XCA_TITLE, "Please enter the new name",
			QLineEdit::Normal, name, &ok, this );
	if (ok && name != nname) {
		db->renamePKI(pki, nname.latin1());
	}
}

// Static Password Callback functions 

int MainWindow::passRead(char *buf, int size, int rwflag, void *userdata)
{
	PASS_INFO *p = (PASS_INFO *)userdata;
	PassRead_UI *dlg = new PassRead_UI(NULL, 0, true);
	if (p != NULL) {
		dlg->image->setPixmap( *keyImg );
		dlg->title->setText(tr(p->title->c_str()));
		dlg->description->setText(tr(p->description->c_str()));
	}
	dlg->pass->setFocus();
	dlg->setCaption(tr(XCA_TITLE));
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
		dlg->image->setPixmap( *keyImg );
		dlg->title->setText(tr(p->title->c_str()));
		dlg->description->setText(tr(p->description->c_str()));
	}
	dlg->passA->setFocus();
	dlg->setCaption(tr(XCA_TITLE));
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
	return str;
}

bool MainWindow::opensslError(pki_base *pki)
{
	string err;

	if (!pki) {
		QMessageBox::warning(this,tr(XCA_TITLE), tr("The system detected a NULL pointer, maybe the system is out of memory" ));
		qFatal("NULL pointer detected - Exiting");
	}
	
	if (( err = pki->getError()) != "") { 
		QMessageBox::warning(this,tr(XCA_TITLE), tr("The following error occured")+
			" (" + QString::fromLatin1(pki->getClassName().c_str()) +") :"+
			QString::fromLatin1(err.c_str()));
		return true;
	}
	return false;
}
	
void MainWindow::Error(errorEx &err)
{
	if (err.isEmpty()) {
		CERR("Empty error Exception silently ignored");
		return;
	}
	QMessageBox::warning(this,tr(XCA_TITLE), tr("The following error occured:") + "\n" +
			QString::fromLatin1(err.getCString()));
}

void MainWindow::crashApp()
{
	pki_base * nullpointer = NULL;
	CERR("------> CRASHING the Application <----------");
	nullpointer->getDescription();
}

void MainWindow::dberr(const char *errpfx, char *msg)
{
	CERR(errpfx << " " << msg);
}

void MainWindow::setPath(QFileDialog *dlg)
{
	string wd = settings->getString("workingdir");	
	if (!wd.empty()) {
		dlg->setDir(QString(wd.c_str()));
	}
}

QString MainWindow::getPath()
{
	QString x = settings->getString("workingdir").c_str();	
	return x;
}

void MainWindow::newPath(QFileDialog *dlg)
{
	newPath( dlg->dirPath() );
}

void MainWindow::newPath(QString str)
{
	settings->putString("workingdir", str.latin1());
}

bool MainWindow::mkDir(QString dir)
{
	int ret = mkdir(dir.latin1(), S_IRUSR | S_IWUSR | S_IXUSR);
	if (ret) {
		QString desc = " (";
		desc += strerror(ret);
	      	desc += ")";
		QMessageBox::critical(this,tr(XCA_TITLE), 
			tr("Error creating: ") + dir + desc);
		return false;
	}
	return true;
}

