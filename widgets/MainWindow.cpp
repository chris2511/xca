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
#include "ImportMulti.h"
#include <qapplication.h>
#include <qclipboard.h>
#include <qmessagebox.h>
#include <qlabel.h>
#include <qpushbutton.h>
#include <qlistview.h>
#include <qlineedit.h>
#include <qtextbrowser.h>
#include "lib/exception.h"
#include "lib/pki_pkcs12.h"
#include "view/KeyView.h"
#include "view/ReqView.h"
#include "view/CertView.h"
#include "view/TempView.h"
#include "view/CrlView.h"
#include "lib/load_obj.h"
#include "lib/pass_info.h"
#include "lib/func.h"
#include "ui/PassRead.h"
#include "ui/PassWrite.h"

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
DbEnv *MainWindow::dbenv = NULL;

NIDlist *MainWindow::eku_nid = NULL;
NIDlist *MainWindow::dn_nid = NULL;
MainWindow::MainWindow(QWidget *parent, const char *name ) 
	:MainWindow_UI(parent, name)
{
	setCaption(tr(XCA_TITLE));
	dbfile = DBFILE;
	dbenv = NULL;
	global_tid = NULL;

	baseDir = getBaseDir();
	
	init_menu();
	
	init_images();
	do_connections();
	
#ifdef MDEBUG	
	CRYPTO_malloc_debug_init();
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	fprintf(stderr, "malloc() debugging on.\n");
#endif

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	read_cmdline();
	if (exitApp) return;
	init_baseDir();
	emit init_database();
}

void MainWindow::init_baseDir()
{
	static bool done = false;
	if (done) return;
	cerr << "base Dir: "<< baseDir << endl; 
	QDir d(baseDir);
	if ( ! d.exists() && !d.mkdir(baseDir)) {
		QMessageBox::warning(this,tr(XCA_TITLE),
			QString::fromLatin1("Could not create: ") + baseDir);
		qFatal(  QString::fromLatin1("Could not create: ") +  baseDir );
	}
	done = true;
	NIDlist nl;
	nl.clear();
	QString prefix = getPrefix();

	/* read in all our own OIDs */
	initOIDs(baseDir);
	
	nl = readNIDlist(baseDir + QDir::separator() + "eku.txt");
	if (nl.count() == 0)
		nl = readNIDlist(prefix + QDir::separator() + "eku.txt");
	eku_nid = new NIDlist(nl);
	nl.clear();
	nl = readNIDlist(baseDir + QDir::separator() + "dn.txt");
	if (nl.count() == 0)
		nl = readNIDlist(prefix + QDir::separator() + "dn.txt");
	dn_nid = new NIDlist(nl);
}


void MainWindow::do_connections()
{
	
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
	connect( BNchangePass, SIGNAL(clicked()), keyList, SLOT(changePasswd()));
	
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
}

void MainWindow::init_images()
{
	
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
	pki_x509req::icon[2] = loadImg("spki.png");
	pki_x509::icon[0] = loadImg("validcert.png");
	pki_x509::icon[1] = loadImg("validcertkey.png");
	pki_x509::icon[2] = loadImg("invalidcert.png");
	pki_x509::icon[3] = loadImg("invalidcertkey.png");
	pki_x509::icon[4] = loadImg("revoked.png");
	pki_temp::icon = loadImg("template.png");			     
	pki_crl::icon = loadImg("crl.png");			     
}		
	
void MainWindow::read_cmdline()
{
	int cnt = 1, opt = 0 , type = 1;
	char *arg = NULL;
	pki_base *item = NULL;
	load_base *lb = NULL;
	exitApp = 0;
	
	ImportMulti *dlgi = NULL;
	dlgi = new ImportMulti(this, NULL, true); 
	
	while (cnt < qApp->argc()) {
		arg = qApp->argv()[cnt];
		if (arg[0] == '-') { // option
			if (lb) delete lb;
			opt = 1; lb = NULL; type = 1;
			switch (arg[1]) {
				case 'c' : lb = new load_cert(); break;
				case 'r' : lb = new load_req(); break;
				case 'k' : lb = new load_key(); break;
				case 'p' : lb = new load_pkcs12(); break;
				case '7' : lb = new load_pkcs7(); break;
				case 'l' : lb = new load_crl(); break;
				case 't' : lb = new load_temp(); break;
				case 'd' : type = 1; break;
				case 'b' : type = 2; break;
				case 'v' : cerr << XCA_TITLE " Version " << VER << endl; 
						   opt=0; exitApp=1; break;
				case 'x' : exitApp = 1; opt=0; break;
				default  : cmd_help(tr("no such option: ") + arg );
			}
			if (arg[2] != '\0' && opt==1) {
				 arg+=2;
			}
			else {
				cnt++;
				continue;
			}
		}
		if (lb) {
			item = NULL;
			try {
				item = lb->loadItem(arg);
				dlgi->addItem(item);
			}
			catch (errorEx &err) {
				Error(err);
				if (item) {
					delete item;
					item = NULL;
				}
			}
		}
		else {
			switch (type) {
				case 1 : dbfile = arg; break;
				case 2 : baseDir = arg; init_baseDir(); break;
				default  : cmd_help(tr("I'm puzzled: this should not happen ! ") );
			}
		}
		
		cnt++;
	}

	connect( dlgi, SIGNAL(init_database()), this, SLOT(init_database()));
	dlgi->execute(1); /* force showing of import dialog */
	delete dlgi;
}	


MainWindow::~MainWindow() 
{
	close_database();
	ERR_free_strings();
	EVP_cleanup();
	OBJ_cleanup();
	if (eku_nid)
		delete eku_nid;
	if (dn_nid)
		delete dn_nid;
#ifdef MDEBUG	
	fprintf(stderr, "Memdebug:\n");
	CRYPTO_mem_leaks_fp(stderr);
#endif
}

int MainWindow::initPass()
{
	pass_info p(tr("New Password"), 
		tr("Please enter a password, that will be used to encrypt your private keys in the database-file"));
	QString passHash = settings->getString("pwhash");
	if (passHash.isEmpty()) {
		int keylen = passWrite((char *)pki_key::passwd, 25, 0, &p);
		if (keylen == 0) return 0;
		pki_key::passwd[keylen]='\0';
		settings->putString( "pwhash", md5passwd(pki_key::passwd) );
	}
	else {
		int keylen=0;		
		while (md5passwd(pki_key::passwd) != passHash) {
			if (keylen !=0) QMessageBox::warning(this,tr(XCA_TITLE),
				tr("Password verify error, please try again"));	
			p.setTitle(tr("Password"));
			p.setDescription(tr("Please enter the password for unlocking the database"));
			keylen = passRead(pki_key::passwd, 25, 0, &p);
			if (keylen == 0) return 0;
			pki_key::passwd[keylen]='\0';
	    }
	}
	return 1;
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

QString MainWindow::md5passwd(const char *pass)
{

	EVP_MD_CTX mdctx;
	QString str;
	unsigned int n;
	int j;
	char zs[4];
	unsigned char m[EVP_MAX_MD_SIZE];
	EVP_DigestInit(&mdctx, EVP_md5());
	EVP_DigestUpdate(&mdctx, pass, strlen(pass));
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
	QString msg =  tr("The following error occured:") + "\n" + err.getString();
	int ret = QMessageBox::warning(NULL, XCA_TITLE, msg, tr("&OK"), tr("Copy to Clipboard"));
	if (ret == 1) {
		QClipboard *cb = QApplication::clipboard();
		cb->setText(msg);
	}
}

void MainWindow::dberr(const char *errpfx, char *msg)
{
	errorEx e(QString(errpfx) + "\n" + msg);
	Error(e);
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
