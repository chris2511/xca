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


QPixmap *MainWindow::keyImg = NULL, *MainWindow::csrImg = NULL, *MainWindow::certImg = NULL, *MainWindow::tempImg = NULL;


MainWindow::MainWindow(QWidget *parent, const char *name ) 
	:MainWindow_UI(parent, name)
{
	connect( (QObject *)quitApp, SIGNAL(clicked()), (QObject *)qApp, SLOT(quit()) );
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
	keyImg = loadImg("bigkey.png");
	csrImg = loadImg("bigcsr.png");
	certImg = loadImg("bigcert.png");
	tempImg = loadImg("bigtemp.png");
	initPass();
	keys = new db_key(dbenv, dbfile.latin1(), keyList);
	reqs = new db_x509req(dbenv, dbfile.latin1(), reqList, keys);
	certs = new db_x509(dbenv, dbfile.latin1(), certList, keys);
	temps = new db_temp(dbenv, dbfile.latin1(), tempList);
	bigKey->setPixmap(*keyImg);
	bigCsr->setPixmap(*csrImg);
	bigCert->setPixmap(*certImg);
#ifdef qt3	
	connect( keyList, SIGNAL(itemRenamed(QListViewItem *, int, const QString &)),this, SLOT(renameKey(QListViewItem *, int, const QString &)));
	connect( reqList, SIGNAL(itemRenamed(QListViewItem *, int, const QString &)),this, SLOT(renameReq(QListViewItem *, int, const QString &)));
	connect( certList, SIGNAL(itemRenamed(QListViewItem *, int, const QString &)),this, SLOT(renameCert(QListViewItem *, int, const QString &)));
	connect( tempList, SIGNAL(itemRenamed(QListViewItem *, int, const QString &)),this, SLOT(renameTemp(QListViewItem *, int, const QString &)));
#endif	
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

void MainWindow::renamePKI(db_base *db)
{
        pki_base * pki = db->getSelectedPKI();
        Rename_UI *dlg = new Rename_UI(this,0,true);
        dlg->newName->setText(pki->getDescription().c_str());
        if (dlg->exec()) {
		db->renamePKI(pki, dlg->newName->text().latin1());
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
	
	
