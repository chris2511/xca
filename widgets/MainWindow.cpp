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
 *	written by Eric Young (eay@cryptsoft.com)"
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


//#define MDEBUG
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
#include <qstatusbar.h>
#include <qlist.h>
#include "lib/exception.h"
#include "lib/pki_pkcs12.h"
#include "lib/load_obj.h"
#include "lib/pass_info.h"
#include "lib/func.h"
#include "ui_PassRead.h"
#include "ui_PassWrite.h"


QPixmap *MainWindow::keyImg = NULL, *MainWindow::csrImg = NULL,
	*MainWindow::certImg = NULL, *MainWindow::tempImg = NULL,
	*MainWindow::nsImg = NULL, *MainWindow::revImg = NULL,
	*MainWindow::appIco = NULL;

db_key *MainWindow::keys = NULL;
db_x509req *MainWindow::reqs = NULL;
db_x509	*MainWindow::certs = NULL;
db_temp	*MainWindow::temps = NULL;
db_crl	*MainWindow::crls = NULL;

NIDlist *MainWindow::eku_nid = NULL;
NIDlist *MainWindow::dn_nid = NULL;
NIDlist *MainWindow::aia_nid = NULL;


MainWindow::MainWindow(QWidget *parent )
	:QMainWindow(parent)
{
	dbindex = new QLabel();
	dbindex->setFrameStyle(QFrame::Plain | QFrame::NoFrame);
	dbindex->setMargin(6);

	statusBar()->addWidget(dbindex, 1);
	force_load = 0;

	setupUi(this);
	setWindowTitle(tr(XCA_TITLE));

	wdList << keyButtons << reqButtons << certButtons <<
		tempButtons <<	crlButtons;
	init_menu();
	setItemEnabled(false);

	init_images();
	homedir = getHomeDir();

	// FIXME: Change pass isn't functional yet.
	BNchangePass->setDisabled(true);

#ifdef MDEBUG
	CRYPTO_malloc_debug_init();
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	fprintf(stderr, "malloc() debugging on.\n");
#endif

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	/* read in all our own OIDs */
	initOIDs();

	eku_nid = read_nidlist("eku.txt");
	dn_nid = read_nidlist("dn.txt");
	aia_nid = read_nidlist("aia.txt");
}

void MainWindow::setItemEnabled(bool enable)
{
	foreach(QWidget *w, wdList) {
		w->setEnabled(enable);
	}
	foreach(QAction *a, acList) {
		a->setEnabled(enable);
	}
}

/* creates a new nid list from the given filename */
NIDlist *MainWindow::read_nidlist(QString name)
{
	NIDlist nl;
	name = QDir::separator() + name;

#ifndef WIN32
	/* first try $HOME/xca/ */
	nl = readNIDlist(QDir::homePath() + QDir::separator() + ".xca" + name);

	if (nl.count() == 0){
		/* next is /etx/xca/... */
		nl = readNIDlist(QString(ETC) + name);
	}
#endif
	if (nl.count() == 0) {
		/* look at /usr/(local/)share/xca/ */
		nl = readNIDlist(getPrefix() + name);
	}
	return new NIDlist(nl);
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
	setWindowIcon(*appIco);
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
	int cnt = 1, opt = 0;
	char *arg = NULL;
	pki_base *item = NULL;
	load_base *lb = NULL;
	exitApp = 0;
	ImportMulti *dlgi = new ImportMulti(this);
	while (cnt < qApp->argc()) {
		arg = qApp->argv()[cnt];
		if (arg[0] == '-') { // option
			if (lb)
				delete lb;
			opt = 1; lb = NULL;
			switch (arg[1]) {
				case 'c' : lb = new load_cert(); break;
				case 'r' : lb = new load_req(); break;
				case 'k' : lb = new load_key(); break;
				case 'p' : lb = new load_pkcs12(); break;
				case '7' : lb = new load_pkcs7(); break;
				case 'l' : lb = new load_crl(); break;
				case 't' : lb = new load_temp(); break;
				case 'P' : lb = new load_pem(); break;
				case 'd' : force_load=1; break;
				case 'v' : fprintf(stderr, XCA_TITLE " Version " VER "\n");
						   opt=0; exitApp=1; break;
				case 'x' : exitApp = 1; opt=0; break;
				default  : cmd_help((char*)(QString(tr("no such option: ")) + arg).data() );
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
				if (item) {
					delete item;
					item = NULL;
				}
			}
		} else {
			dbfile = arg;
			homedir = dbfile.left(dbfile.lastIndexOf(QDir::separator()));
			init_database();
		}

		cnt++;
	}
	dlgi->execute(1); /* force showing of import dialog */
	delete dlgi;
}

void MainWindow::loadPem()
{
	load_pem l;
	if (keys)
		keys->load_default(l);
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
	if (aia_nid)
		delete aia_nid;
	delete dbindex;
#ifdef MDEBUG
	fprintf(stderr, "Memdebug:\n");
	CRYPTO_mem_leaks_fp(stderr);
#endif
}

int MainWindow::initPass()
{
	db mydb(dbfile);
	char *pass;
	pki_key::passHash = QString();

	pass_info p(tr("New Password"),
		tr("Please enter a password, that will be used to encrypt your private keys in the database-file"), this);
	if (!mydb.find(setting, "pwhash")) {
		if ((pass = (char *)mydb.load(NULL))) {
			pki_key::passHash = pass;
			free(pass);
		}
	}
	if (pki_key::passHash.isEmpty()) {
		int keylen = passWrite((char *)pki_key::passwd, MAX_PASS_LENGTH-1, 0, &p);
		if (keylen < 0)
			return 0;
		pki_key::passwd[keylen]='\0';
		pki_key::passHash = pki_key::md5passwd(pki_key::passwd);
		mydb.set((const unsigned char *)CCHAR(pki_key::passHash),
				pki_key::passHash.length()+1, 1, setting, "pwhash");
	}
	else {
		int keylen=0;
		while (pki_key::md5passwd(pki_key::passwd) != pki_key::passHash) {
			if (keylen !=0) QMessageBox::warning(this,tr(XCA_TITLE),
				tr("Password verify error, please try again"));
			p.setTitle(tr("Password"));
			p.setDescription(tr("Please enter the password for unlocking the database"));
			keylen = passRead(pki_key::passwd, MAX_PASS_LENGTH-1, 0, &p);
			if (keylen < 0)
				return 1;
			pki_key::passwd[keylen]='\0';
	    }
	}
	return 1;
}

// Static Password Callback functions

int MainWindow::passRead(char *buf, int size, int rwflag, void *userdata)
{
	int ret = -1;
	pass_info *p = (pass_info *)userdata;
	Ui::PassRead ui;
	QDialog *dlg = new QDialog(p->getWidget());
	ui.setupUi(dlg);
	if (p != NULL) {
		ui.image->setPixmap( *keyImg );
		ui.description->setText(p->getDescription());
		dlg->setWindowTitle(p->getTitle());
	}

	if (dlg->exec()) {
	   QString x = ui.pass->text();
	   strncpy(buf, x.toAscii(), size);
	   ret = x.length();
	}
	delete dlg;
	return ret;
}


int MainWindow::passWrite(char *buf, int size, int rwflag, void *userdata)
{
	int ret = -1;
	pass_info *p = (pass_info *)userdata;
	Ui::PassWrite ui;
	QDialog *dlg = new QDialog(p->getWidget());
	ui.setupUi(dlg);
	if (p != NULL) {
		ui.image->setPixmap( *keyImg );
		ui.description->setText(p->getDescription());
		dlg->setWindowTitle(p->getTitle());
	}
	dlg->show();
	dlg->activateWindow();
	ui.passA->setFocus();

	while (dlg->exec()) {
		QString A = ui.passA->text();
		QString B = ui.passB->text();
		if (A == B) {
			strncpy(buf, A.toAscii(), size);
			ret = A.length();
			break;
		} else {
			QMessageBox::warning(p->getWidget(), tr(XCA_TITLE), tr("Password missmatch"));
		}
	}
	delete dlg;
	return ret;
}

void MainWindow::Error(errorEx &err)
{
	if (err.isEmpty()) return;
	QString msg =  tr("The following error occured:") + "\n" + err.getString();
	int ret = QMessageBox::warning(qApp->activeWindow(), XCA_TITLE,
			msg, tr("&OK"), tr("Copy to Clipboard"));
	if (ret == 1) {
		QClipboard *cb = QApplication::clipboard();
		cb->setText(msg);
	}
}

QString MainWindow::getPath()
{
	return workingdir;
}

void MainWindow::setPath(QString str)
{
	db mydb(dbfile);
	workingdir = str;
	mydb.set((const unsigned char *)CCHAR(str), str.length()+1, 1, setting, "workingdir");
}

void MainWindow::connNewX509(NewX509 *nx)
{
	connect( nx, SIGNAL(genKey()), keys, SLOT(newItem()) );
	connect( keys, SIGNAL(keyDone(QString)), nx, SLOT(newKeyDone(QString)) );
	connect( nx, SIGNAL(showReq(QString)), reqs, SLOT(showItem(QString)));
}

/* Dear code reader,
 * this is an evil hack. Originally I compiled MW_menu.cpp separately
 * and linked it to the application, but the mingw32 linker
 * segfaults. Thus I include the file here and remove it from the Makefile
 * and the linker works.
 * There is a FIXME and a warning */
#warning inclde "MW_menu.cpp"
#include "MW_menu.cpp"
