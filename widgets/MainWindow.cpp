/* vi: set sw=4 ts=4: */
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
#include <qpushbutton.h>
#include <qlistview.h>
#include <qlineedit.h>
#include "lib/pki_pkcs12.h"
#include "view/KeyView.h"
#include "view/ReqView.h"
#include "view/CertView.h"
#include "view/TempView.h"
#include "view/CrlView.h"
#include "lib/pass_info.h"
#include "lib/func.h"
#include "ui/PassRead.h"
#include "ui/PassWrite.h"

#ifdef WIN32
#include <Shlobj.h>
#endif



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

	getBaseDir();
	QDir d(baseDir);
        if ( ! d.exists() && !d.mkdir(baseDir)) {
		QMessageBox::warning(this,tr(XCA_TITLE), QString::fromLatin1("Could not create ") + baseDir);
		qFatal(  QString::fromLatin1("Couldnt create: ") +  baseDir );
	}

	init_images();
	
	connect( keyList, SIGNAL(init_database()), this, SLOT(init_database()));
	connect( reqList, SIGNAL(init_database()), this, SLOT(init_database()));
	connect( certList, SIGNAL(init_database()), this, SLOT(init_database()));
	connect( tempList, SIGNAL(init_database()), this, SLOT(init_database()));
	connect( crlList, SIGNAL(init_database()), this, SLOT(init_database()));

	connect( BNnewKey, SIGNAL(clicked()), keyList, SLOT(newItem()));
	connect( BNexportKey, SIGNAL(clicked()), keyList, SLOT(store()));
	connect( BNimportKey, SIGNAL(clicked()), keyList, SLOT(load()));
	connect( BNdetailsKey, SIGNAL(clicked()), keyList, SLOT(showItem()));
	connect( BNdeleteKey, SIGNAL(clicked()), keyList, SLOT(deleteItem()));
	
	connect( BNnewReq, SIGNAL(clicked()), reqList, SLOT(newItem()));
	connect( BNimportReq, SIGNAL(clicked()), reqList, SLOT(load()));
	connect( BNdetailsReq, SIGNAL(clicked()), reqList, SLOT(showItem()));
	connect( BNdeleteReq, SIGNAL(clicked()), reqList, SLOT(deleteItem()));

	connect( BNnewCert, SIGNAL(clicked()), certList, SLOT(newItem()));
	connect( BNimportCert, SIGNAL(clicked()), certList, SLOT(load()));
	connect( BNexportCert, SIGNAL(clicked()), certList, SLOT(store()));
	connect( BNdetailsCert, SIGNAL(clicked()), certList, SLOT(showItem()));
	connect( BNdeleteCert, SIGNAL(clicked()), certList, SLOT(deleteItem()));
	connect( BNimportPKCS12, SIGNAL(clicked()), certList, SLOT(loadPKCS12()));
	connect( BNimportPFX, SIGNAL(clicked()), certList, SLOT(loadPKCS12()));
	connect( BNimportPKCS7, SIGNAL(clicked()), certList, SLOT(loadPKCS7()));
	connect( BNviewState, SIGNAL(clicked()), this, SLOT(changeView()));
	
	connect( BNemptyTemp, SIGNAL(clicked()), tempList, SLOT(newEmptyTemp()));
	connect( BNcaTemp, SIGNAL(clicked()), tempList, SLOT(newCaTemp()));
	connect( BNclientTemp, SIGNAL(clicked()), tempList, SLOT(newClientTemp()));
	connect( BNserverTemp, SIGNAL(clicked()), tempList, SLOT(newServerTemp()));
	connect( BNdeleteTemp, SIGNAL(clicked()), tempList, SLOT(deleteItem()));
	connect( BNchangeTemp, SIGNAL(clicked()), tempList, SLOT(alterTemp()));
	connect( BNimportTemp, SIGNAL(clicked()), tempList, SLOT(load()));
	connect( BNexportTemp, SIGNAL(clicked()), tempList, SLOT(store()));
	
	connect( BNimportCrl, SIGNAL(clicked()), crlList, SLOT(load()));
	connect( BNdetailsCrl, SIGNAL(clicked()), crlList, SLOT(showItem()));
	connect( BNdeleteCrl, SIGNAL(clicked()), crlList, SLOT(deleteItem()));
	
	connect( certList, SIGNAL(connNewX509(NewX509 *)), this, SLOT(connNewX509(NewX509 *)) );
	connect( reqList, SIGNAL(connNewX509(NewX509 *)), this, SLOT(connNewX509(NewX509 *)) );
	
	connect( reqList, SIGNAL(newCert(pki_x509req *)),
		certList, SLOT(newCert(pki_x509req *)) );
	connect( certList, SIGNAL(genCrl(pki_x509 *)),
		crlList, SLOT(newItem(pki_x509 *)) );
	connect( tempList, SIGNAL(newCert(pki_temp *)),
		certList, SLOT(newCert(pki_temp *)) );
	connect( tempList, SIGNAL(newReq(pki_temp *)),
		reqList, SLOT(newItem(pki_temp *)) );
	
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	read_cmdline();
	if (!exitApp)
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
	pki_key::icon[0] = loadImg("key.png");
	pki_key::icon[1] = loadImg("halfkey.png");
	pki_x509req::icon[0] = loadImg("req.png");
	pki_x509req::icon[1] = loadImg("reqkey.png");
	pki_x509::icon[0] = loadImg("validcert.png");
	pki_x509::icon[1] = loadImg("validcertkey.png");
	pki_x509::icon[2] = loadImg("invalidcert.png");
	pki_x509::icon[3] = loadImg("invalidcertkey.png");
	pki_temp::icon = loadImg("template.png");			     
	pki_crl::icon = loadImg("crl.png");			     
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
					   printf("%s Version %s\n", 
						   XCA_TITLE, VER);
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
				keyList->showItem(key, true);
				break;
			case XCA_CERT : 
		 		cert = new pki_x509(arg);
				certList->showItem(cert, true);
				break;
			case XCA_REQ : 
		 		req = new pki_x509req(arg);
				reqList->showItem(req, true);
				break;
			case XCA_P12 : 
		 		p12 = new pki_pkcs12(arg, &MainWindow::passRead);
				//certList->insertP12(p12);
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
		dbenv->open(QFile::encodeName(baseDir), DB_RECOVER | DB_INIT_TXN | \
				DB_INIT_MPOOL | DB_INIT_LOG | DB_INIT_LOCK | \
				DB_CREATE | DB_PRIVATE , 0600 );
		dbenv->txn_begin(NULL, &global_tid, 0);
#ifndef DB_AUTO_COMMIT
#define DB_AUTO_COMMIT 0
#endif
		dbenv->set_flags(DB_AUTO_COMMIT,1);
	}
	catch (DbException &err) {
		DBEX(err);
		QString e = err.what();
		e += QString::fromLatin1(" (") + baseDir + QString::fromLatin1(")");
		qFatal(e);
	}
	try {
		settings = new db_base(dbenv, dbfile, "settings",global_tid);
		initPass();
		keys = new db_key(dbenv, dbfile, global_tid);
		reqs = new db_x509req(dbenv, dbfile, keys, global_tid);
		certs = new db_x509(dbenv, dbfile, keys, global_tid);
		temps = new db_temp(dbenv, dbfile, global_tid);
		crls = new db_crl(dbenv, dbfile, global_tid);
		reqs->setKeyDb(keys);
		certs->setKeyDb(keys);
	
		keyList->setDB(keys);
		reqList->setDB(reqs);
		certList->setDB(certs);
		tempList->setDB(temps);
		crlList->setDB(crls);
	}
	catch (errorEx &err) {
		Error(err);
	}
	catch (DbException &err) {
		DBEX(err);
		qFatal(err.what());
	}
	connect( keys, SIGNAL(newKey(pki_key *)),
		certs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		certs, SLOT(delKey(pki_key *)) );
	connect( keys, SIGNAL(newKey(pki_key *)),
		reqs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		reqs, SLOT(delKey(pki_key *)) );
	
}		



MainWindow::~MainWindow() 
{
	ERR_free_strings();
	EVP_cleanup();
	if (dbenv) {
		delete(crls);
		delete(reqs);
		delete(certs);
		delete(temps);
		delete(keys);
		delete(settings);
		global_tid->commit(0);
		dbenv->close(0);
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
	if (err.isEmpty()) return;
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

NewX509 *MainWindow::newX509()
{
	return new NewX509(NULL, 0, true);
}

void MainWindow::connNewX509(NewX509 *nx)
{
	connect( (const QObject *)nx->genKeyBUT, SIGNAL(clicked()), keyList, SLOT(newItem()) );
	connect( nx, SIGNAL(genKey()), keyList, SLOT(newItem()) );
	connect( keyList, SIGNAL(keyDone(QString)), nx, SLOT(newKeyDone(QString)) );
}

void MainWindow::changeView()
{
	certList->changeView(BNviewState);
}

QString MainWindow::getBaseDir()
{
#ifdef WIN32
	unsigned char reg_path_buf[255] = "";
	TCHAR data_path_buf[255];

	// verification registry keys
	LONG lRc;
    HKEY hKey;
	DWORD dwDisposition;
	DWORD dwLength = 255;
    lRc=RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\xca",0,KEY_READ, &hKey);
    if(lRc!= ERROR_SUCCESS){
		QMessageBox::warning(NULL, XCA_TITLE,
			"Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca' not found. ReInstall Xca.");
		qFatal("");
	}
    else {
		lRc=RegQueryValueEx(hKey,"Install_Dir",NULL,NULL, reg_path_buf, &dwLength);
        if(lRc!= ERROR_SUCCESS){
			QMessageBox::warning(NULL, XCA_TITLE,
				"Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found. ReInstall Xca.");		
			qFatal("");
		}
		lRc=RegCloseKey(hKey);
	}
	lRc=RegOpenKeyEx(HKEY_CURRENT_USER,"Software\\xca",0,KEY_ALL_ACCESS, &hKey);
    if(lRc!= ERROR_SUCCESS)
    {
		//First run for current user
		lRc=RegCloseKey(hKey);
		lRc=RegCreateKeyEx(HKEY_CURRENT_USER,"Software\\xca",0,NULL,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,
		NULL,&hKey, &dwDisposition);
		
		//setup data dir for current user
		OSVERSIONINFOEX osvi;
		BOOL bOsVersionInfoEx;
		LPITEMIDLIST pidl=NULL; 

		ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

		if(!(bOsVersionInfoEx=GetVersionEx((OSVERSIONINFO*)&osvi))){
			osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
			if (! GetVersionEx ( (OSVERSIONINFO *) &osvi) ) return FALSE;
		}
		if (osvi.dwPlatformId == VER_PLATFORM_WIN32_NT){
			if(SUCCEEDED(SHGetSpecialFolderLocation(NULL,CSIDL_APPDATA,&pidl))){
				SHGetPathFromIDList(pidl,data_path_buf);
				lstrcat(data_path_buf, "\\xca");	 
			}
		}else{
			strncpy(data_path_buf,(char *)reg_path_buf,255);
			strcat(data_path_buf,"\\data");
		}
		baseDir = QString::fromLocal8Bit(data_path_buf);
		// save in registry
		lRc=RegSetValueEx(hKey,"data_path",0,REG_SZ,(BYTE*)data_path_buf, 255);
		lRc=RegCloseKey(hKey);
		QMessageBox::warning(this,tr(XCA_TITLE), QString::fromLatin1("New data dir create:")+ baseDir);
		QMessageBox::warning(this,tr(XCA_TITLE), QString::fromLatin1("WARNING: If you have updated your 'xca' application \n you have to copy your 'xca.db' from 'C:\\PROGAM FILES\\XCA\\' to ") + baseDir + QString::fromLatin1(" \n or change HKEY_CURRENT_USER->Software->xca->data_path key"));
        }
	else{
		dwLength = sizeof(data_path_buf);
		lRc=RegQueryValueEx(hKey,"data_path",NULL,NULL, (BYTE*)data_path_buf, &dwLength);
		if ((lRc != ERROR_SUCCESS)) {
			QMessageBox::warning(NULL,tr(XCA_TITLE), "Registry Key: 'HKEY_CURRENT_USER->Software->xca->data_path' not found.");
			//recreate data dir for current user
			OSVERSIONINFOEX osvi;
			BOOL bOsVersionInfoEx;
			LPITEMIDLIST pidl=NULL; 

			ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
			osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

			if(!(bOsVersionInfoEx=GetVersionEx((OSVERSIONINFO*)&osvi))){
				osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
				if (! GetVersionEx ( (OSVERSIONINFO *) &osvi) ) return FALSE;
			}
			if (osvi.dwPlatformId == VER_PLATFORM_WIN32_NT){
				if(SUCCEEDED(SHGetSpecialFolderLocation(NULL,CSIDL_APPDATA,&pidl))){
					SHGetPathFromIDList(pidl,data_path_buf);
					lstrcat(data_path_buf, "\\xca");	  
				}
			}else{
				strncpy(data_path_buf,(char *)reg_path_buf,255);
				strcat(data_path_buf,"\\data");
			}
			baseDir = QString::fromLocal8Bit(data_path_buf);
			// save in registry
			lRc=RegSetValueEx(hKey,"data_path",0,REG_SZ,(BYTE*)data_path_buf, 255);
			lRc=RegCloseKey(hKey);
			QMessageBox::warning(this,tr(XCA_TITLE), QString::fromLatin1("data dir:")+ baseDir);
		}

		lRc=RegCloseKey(hKey);
		baseDir = QString::fromLocal8Bit(data_path_buf);
	}
// 

#else	
	baseDir = QDir::homeDirPath();
	baseDir += QDir::separator();
	baseDir += BASE_DIR;
#endif
	return baseDir;
}
