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
#include "view/KeyView.h"
#include "view/ReqView.h"
#include "view/CertView.h"
#include "view/CrlView.h"
#include "view/TempView.h"


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
		QString e = err.what();
		e += QString::fromLatin1(" (") + baseDir + QString::fromLatin1(")");
		global_tid->abort();
	    dbenv->close(0);
	    dbenv = NULL;
		return;
			
	}
	cerr << "Opening database: "<< dbfile << endl;
	try {
		settings = new db_base(dbenv, dbfile, "settings",global_tid, NULL);
		if (!initPass()) {
			/* password error */
			delete settings; settings = NULL;
			global_tid->abort();
		    dbenv->close(0);
		    pki_key::erasePasswd();
		    dbenv = NULL;
			return;
		}
		keys = new db_key(dbenv, dbfile, global_tid, keyList);
		reqs = new db_x509req(dbenv, dbfile, keys, global_tid, reqList);
		certs = new db_x509(dbenv, dbfile, keys, global_tid, certList);
		temps = new db_temp(dbenv, dbfile, global_tid, tempList);
		crls = new db_crl(dbenv, dbfile, global_tid, crlList);
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
		qFatal(err.what());
	}
	
	setCaption(QString(XCA_TITLE) + " - " + dbfile);
	
	connect( keys, SIGNAL(newKey(pki_key *)),
		certs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		certs, SLOT(delKey(pki_key *)) );
	connect( keys, SIGNAL(newKey(pki_key *)),
		reqs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		reqs, SLOT(delKey(pki_key *)) );
	
}		

void MainWindow::close_database()
{
	if (!dbenv) return;
										
	delete(crls);
	delete(reqs);
	delete(certs);
	delete(temps);
	delete(keys);
	delete(settings);
	crls = NULL;
	reqs = NULL;
	certs = NULL;
	temps = NULL;
	keys = NULL;
	settings = NULL;
	crlList->rmDB(crls);
	certList->rmDB(certs);
	reqList->rmDB(reqs);
	tempList->rmDB(temps);
	keyList->rmDB(keys);
	global_tid->commit(0);
	dbenv->close(0);
	pki_key::erasePasswd();
	dbenv = NULL;
}

