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
#include <qapplication.h>
#include <qmessagebox.h>
#include <qlabel.h>
#include "lib/pki_pkcs12.h"
#include "KeyView.h"
#include "ReqView.h"
#include "CertView.h"
#include "TempView.h"
#include "lib/pass_info.h"
#include "PassRead.h"
#include "PassWrite.h"

QPixmap *MainWindow::keyImg = NULL, *MainWindow::csrImg = NULL,
	*MainWindow::certImg = NULL, *MainWindow::tempImg = NULL,
	*MainWindow::nsImg = NULL, *MainWindow::revImg = NULL,
	*MainWindow::appIco = NULL;

db_key *MainWindow::keys = NULL;
db_x509req *MainWindow::reqs = NULL;
db_x509	*MainWindow::certs = NULL;
db_temp	*MainWindow::temps = NULL;
db_base	*MainWindow::settings = NULL;
db_crl	*MainWindow::crls = NULL;


MainWindow::MainWindow(QWidget *parent, const char *name ) 
	:MainWindow_UI(parent, name)
{
	connect( (QObject *)quitApp, SIGNAL(clicked()), (QObject *)qApp, SLOT(quit()) );
	QString cpr = "(c) 2002 by Christian@Hohnstaedt.de - Version: ";
	copyright->setText(cpr + VER);
	setCaption(tr(XCA_TITLE));
	dbfile="xca.db";
	dbenv = NULL;
	global_tid = NULL;


#ifdef WIN32
	unsigned char reg_path_buf[255] = "";
	char data_path_buf[255] = "";
// verification registry keys
	LONG lRc;
    HKEY hKey;
	DWORD dwDisposition;
	DWORD dwLength = 255;
    lRc=RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\xca",0,KEY_READ, &hKey);
    if(lRc!= ERROR_SUCCESS){
	    QMessageBox::warning(NULL,tr(XCA_TITLE), "Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca' not found . ReInstall Xca.");
		qFatal("");
	}
    else {
		lRc=RegQueryValueEx(hKey,"Install_Dir",NULL,NULL, reg_path_buf, &dwLength);
        if(lRc!= ERROR_SUCCESS){
	        QMessageBox::warning(NULL,tr(XCA_TITLE), "Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found. ReInstall Xca.");		
			qFatal("");
		}
		lRc=RegCloseKey(hKey);
	}
	lRc=RegOpenKeyEx(HKEY_CURRENT_USER,"Software\\xca",0,KEY_ALL_ACCESS, &hKey);
        if(lRc!= ERROR_SUCCESS)
        {//First run for current user
                lRc=RegCloseKey(hKey);
                lRc=RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\xca",0,NULL,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
                NULL,&hKey, &dwDisposition);
		//setup data dir for current user
				DWORD ret_val;
				ret_val = ExpandEnvironmentStrings("%USERPROFILE%", data_path_buf, 255);
				strcat(data_path_buf,"\\Application Data\\xca"); //WinNT  - %USERPROFILE%\Application Data\xca
				if (strncmp(data_path_buf,"%USERPROFILE%",13)==0){ // win9x - %Program files%\xca\data
					strncpy(data_path_buf,(char *)reg_path_buf,255);
					strcat(data_path_buf,"\\data");
				}
				baseDir = data_path_buf;
				if (ret_val > 255) {
					QMessageBox::warning(this,tr(XCA_TITLE), "Your %USERPROFILE% is too long");
					lRc=RegCloseKey(hKey);
					qFatal(  "Couldnt create: " +  baseDir );
				}
		// save in registry
                lRc=RegSetValueEx(hKey,"data_path",0,REG_SZ,(BYTE*)data_path_buf, 255);
                lRc=RegCloseKey(hKey);
				QMessageBox::warning(this,tr(XCA_TITLE), "New data dir create:"+ baseDir);
				QMessageBox::warning(this,tr(XCA_TITLE), tr("WARNING: If you have updated your 'xca' application you have to copy your 'xca.db' from 'C:\\PROGAM FILES\\XCA\\' to "+ baseDir +" or change HKEY_CURRENT_USER->Software->xca->data_path key"));
        }
		else{
				dwLength = sizeof(data_path_buf);
				lRc=RegQueryValueEx(hKey,"data_path",NULL,NULL, (BYTE*)data_path_buf, &dwLength);
				if ((lRc != ERROR_SUCCESS)) {
					QMessageBox::warning(NULL,tr(XCA_TITLE), "Registry Key: 'HKEY_CURRENT_USER->Software->xca->data_path' not found.");
		//recreate data dir for current user
					DWORD ret_val;
					ret_val = ExpandEnvironmentStrings("%USERPROFILE%", data_path_buf, 255);
					strcat(data_path_buf,"\\Application Data\\xca"); //WinNT  - %USERPROFILE%\Application Data\xca
					if (strncmp(data_path_buf,"%USERPROFILE%",13)==0){ //win9x -  %USERPROFILE% not set %Program files%\xca\data
						strncpy(data_path_buf,(char *)reg_path_buf,255);
						strcat(data_path_buf,"\\data");
					}
					baseDir = data_path_buf;
					if (ret_val > 255) {
						QMessageBox::warning(this,tr(XCA_TITLE), "Your %USERPROFILE% is too long");
						lRc=RegCloseKey(hKey);
						qFatal(  "Couldnt create: " +  baseDir );
					}
		// save in registry
					lRc=RegSetValueEx(hKey,"data_path",0,REG_SZ,(BYTE*)data_path_buf, 255);
					lRc=RegCloseKey(hKey);
					QMessageBox::warning(this,tr(XCA_TITLE), "data dir:"+ baseDir);
				}

			lRc=RegCloseKey(hKey);
			baseDir = data_path_buf;
		}
// 

#else	
	baseDir = QDir::homeDirPath();

	baseDir += QDir::separator();

	baseDir += BASE_DIR;
#endif

	QDir d(baseDir);
        if ( ! d.exists() ){
			if (!d.mkdir(baseDir)) {
				QMessageBox::warning(this,tr(XCA_TITLE), "Could not create " + baseDir);
				qFatal(  "Couldnt create: " +  baseDir );
			}
	}

	
#ifdef qt3	
	connect( keyList, SIGNAL(newPath(QString &)), this, SLOT(newPath(QString &)));
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
QPixmap *MainWindow::loadImg(const char *name )
{
#ifdef WIN32
	static unsigned char PREFIX[100]="";
	if (PREFIX[0] == '\0') {
	  LONG lRc;
      HKEY hKey;
      lRc=RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\xca",0,KEY_READ, &hKey);
      if(lRc!= ERROR_SUCCESS){
        // No key error
	    QMessageBox::warning(NULL,tr(XCA_TITLE), "Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca' not found");		
		PREFIX[0] = '\0';
	  }
      else {
	    ULONG dwLength = 100;
		lRc=RegQueryValueEx(hKey,"Install_Dir",NULL,NULL, PREFIX, &dwLength);
        if(lRc!= ERROR_SUCCESS){
            // No key error
	        QMessageBox::warning(NULL,tr(XCA_TITLE), "Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found");		
		    PREFIX[0] = '\0';
		}
	  }
	lRc=RegCloseKey(hKey);
	}
#endif    
	QString path = (char *)PREFIX;
	path += QDir::separator();
    return new QPixmap(path + name);
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
				keyList->show(key, true);
				MARK
				break;
			case XCA_CERT : 
		 		cert = new pki_x509(arg);
				certList->show(cert, true);
				break;
			case XCA_REQ : 
		 		req = new pki_x509req(arg);
				reqList->show(req, true);
				break;
			case XCA_P12 : 
		 		p12 = new pki_pkcs12(arg, &MainWindow::passRead);
				//insertP12(p12);
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
				DB_CREATE | DB_PRIVATE , 0600 );
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
		settings = new db_base(dbenv, dbfile, "settings",global_tid);
		initPass();
		keys = new db_key(dbenv, dbfile, global_tid);
		reqs = new db_x509req(dbenv, dbfile, global_tid);
		certs = new db_x509(dbenv, dbfile, global_tid);
		temps = new db_temp(dbenv, dbfile, global_tid);
		crls = new db_crl(dbenv, dbfile, global_tid);
		reqs->setKeyDb(keys);
		certs->setKeyDb(keys);
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

void MainWindow::initPass()
{
	pass_info p(tr("New Password"), 
	  tr("Please enter a password, that will be used to encrypt your private keys in the database-file"));
	QString passHash = settings->getString("pwhash");
	if (passHash.isEmpty()) {
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
		p.setTitle(tr("Password"));
		p.setDescription(tr("Please enter the password for unlocking the database"));
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
	pass_info *p = (pass_info *)userdata;
	PassRead_UI *dlg = new PassRead_UI(NULL, 0, true);
	if (p != NULL) {
		dlg->image->setPixmap( *keyImg );
		dlg->title->setText(tr(p->getTitle()));
		dlg->description->setText(tr(p->getDescription()));
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
	pass_info *p = (pass_info *)userdata;
	PassWrite_UI *dlg = new PassWrite_UI(NULL, 0, true);
	if (p != NULL) {
		dlg->image->setPixmap( *keyImg );
		dlg->title->setText(tr(p->getTitle()));
		dlg->description->setText(tr(p->getDescription()));
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

QString MainWindow::md5passwd()
{

	EVP_MD_CTX mdctx;
	QString str;
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
	
void MainWindow::Error(errorEx &err)
{
	if (err.isEmpty()) {
		CERR("Empty error Exception silently ignored");
		return;
	}
	QMessageBox::warning(this,tr(XCA_TITLE), tr("The following error occured:") + "\n" +
			QString::fromLatin1(err.getCString()));
}

void MainWindow::dberr(const char *errpfx, char *msg)
{
	CERR(errpfx << " " << msg);
}

QString MainWindow::getPath()
{
	QString x = settings->getString("workingdir");
	return x;
}

void MainWindow::setPath(QString str)
{
	settings->putString("workingdir", str);
}

NewX509 *MainWindow::newX509(QPixmap *image)
{
	return new NewX509(NULL, 0, keys, reqs, certs, temps, image, nsImg);
}

