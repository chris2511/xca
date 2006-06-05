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
 * http://www.hohnstaedt.de/xca
 * email: christian@hohnstaedt.de
 *
 * $Id$
 *
 */


#include "MainWindow.h"
#include <Qt/qdir.h>
#include <Qt/qstatusbar.h>

void MainWindow::init_database()
{
	initPass();
	fprintf(stderr, "Opening database: %s\n", CCHAR(dbfile));
	keys = new db_key(dbfile, this);
	reqs = new db_x509req(dbfile, this);
	certs = new db_x509(dbfile, this);
	temps = new db_temp(dbfile, this);
	crls = new db_crl(dbfile, this);
#if 0
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

#endif
	connect( keys, SIGNAL(newKey(pki_key *)),
		certs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		certs, SLOT(delKey(pki_key *)) );
	connect( keys, SIGNAL(newKey(pki_key *)),
		reqs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		reqs, SLOT(delKey(pki_key *)) );

	statusBar()->showMessage(tr("Database") + ":" + dbfile);
	keyView->setModel(keys);
	reqView->setModel(reqs);
	certView->setModel(certs);
	tempView->setModel(temps);
	crlView->setModel(crls);

	connect( certs, SIGNAL(connNewX509(NewX509 *)), this,
		SLOT(connNewX509(NewX509 *)) );
	connect( reqs, SIGNAL(connNewX509(NewX509 *)), this,
		SLOT(connNewX509(NewX509 *)) );
}

void MainWindow::dump_database()
{
	QString dirname;

	QFileDialog *dlg = new QFileDialog(this);
	dlg->setWindowTitle(tr("Dump to directory"));
	dlg->setFileMode(QFileDialog::AnyFile);
	if (dlg->exec()) {
		dirname = dlg->selectedFiles()[0];
	}
	delete dlg;

	if (dirname.isEmpty())
		return;

	QDir d(dirname);
	if ( ! d.exists() && !d.mkdir(dirname)) {
		errorEx err("Could not create '" + dirname + "'");
		MainWindow::Error(err);
		return;
	}

	try {
		keys->dump(dirname);
		certs->dump(dirname);
		temps->dump(dirname);
		crls->dump(dirname);
		reqs->dump(dirname);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
}


void MainWindow::close_database()
{
	keyView->setModel(NULL);
	reqView->setModel(NULL);
	certView->setModel(NULL);
	tempView->setModel(NULL);
	crlView->setModel(NULL);

	delete(crls);
	delete(reqs);
	delete(certs);
	delete(temps);
	delete(keys);

	crls = NULL;
	reqs = NULL;
	certs = NULL;
	temps = NULL;
	keys = NULL;
	settings = NULL;

	db mydb(dbfile);
	mydb.shrink( DBFLAG_OUTDATED | DBFLAG_DELETED );
}

/* Asymetric Key buttons */
void MainWindow::on_BNnewKey_clicked(void)
{
	if (keys)
		keys->newItem();
}
void MainWindow::on_BNdeleteKey_clicked(void)
{
	if (keys)
		keys->deleteSelectedItems(keyView);
}
void MainWindow::on_BNdetailsKey_clicked(void)
{
	if (keys)
		keys->showSelectedItems(keyView);
}
void MainWindow::on_BNimportKey_clicked(void)
{
	if(keys)
		keys->load();
}
void MainWindow::on_BNexportKey_clicked(void)
{
	if(keys)
		keys->storeSelectedItems(keyView);
}
void MainWindow::on_keyView_doubleClicked(QModelIndex &m)
{
	printf("Key View double clicked\n");
	if (keys)
		keys->showItem();
}
void MainWindow::on_BNimportPFX_clicked(void)
{
	if(certs)
		certs->loadPKCS12();
}
/* Certificate request buttons */
void MainWindow::on_BNnewReq_clicked(void)
{
	if (reqs)
		reqs->newItem();
}
void MainWindow::on_BNdeleteReq_clicked(void)
{
	if (reqs)
		reqs->deleteSelectedItems(reqView);
}
void MainWindow::on_BNdetailsReq_clicked(void)
{
	if (reqs)
		reqs->showSelectedItems(reqView);
}
void MainWindow::on_BNimportReq_clicked(void)
{
	if (reqs)
		reqs->load();
}
void MainWindow::on_BNexportReq_clicked(void)
{
	if(reqs)
		reqs->storeSelectedItems(reqView);
}

/* Certificate  buttons */
void MainWindow::on_BNnewCert_clicked(void)
{
	if (certs)
		certs->newItem();
}
void MainWindow::on_BNdeleteCert_clicked(void)
{
	if (certs)
		certs->deleteSelectedItems(certView);
}
void MainWindow::on_BNdetailsCert_clicked(void)
{
	if (certs)
		certs->showSelectedItems(certView);
}
void MainWindow::on_BNimportCert_clicked(void)
{
	if (certs)
		certs->load();
}
void MainWindow::on_BNexportCert_clicked(void)
{
	if(certs)
		certs->storeSelectedItems(certView);
}

void MainWindow::on_BNimportPKCS12_clicked(void)
{
	if(certs)
		certs->loadPKCS12();
}

void MainWindow::on_BNimportPKCS7_clicked(void)
{
	if(certs)
		certs->loadPKCS7();
}

/* Template buttons */
void MainWindow::on_BNdeleteTemp_clicked(void)
{
	if (temps)
		temps->deleteSelectedItems(tempView);
}
void MainWindow::on_BNchangeTemp_clicked(void)
{
	if (temps)
		temps->showSelectedItems(tempView);
}
void MainWindow::on_BNimportTemp_clicked(void)
{
	if (temps)
		temps->load();
}
void MainWindow::on_BNexportTemp_clicked(void)
{
	if(temps)
		temps->storeSelectedItems(tempView);
}
void MainWindow::on_BNemptyTemp_clicked(void)
{
	if (temps)
		temps->newEmptyTemp();
}
void MainWindow::on_BNcaTemp_clicked(void)
{
	if (temps)
		temps->newCaTemp();
}
void MainWindow::on_BNserverTemp_clicked(void)
{
	if (temps)
		temps->newServerTemp();
}
void MainWindow::on_BNclientTemp_clicked(void)
{
	if (temps)
		temps->newClientTemp();
}
/* CRL buttons */

void MainWindow::on_BNdeleteCrl_clicked(void)
{
	if (crls)
		crls->deleteSelectedItems(crlView);
}
void MainWindow::on_BNimportCrl_clicked(void)
{
	if (crls)
		crls->load();
}
void MainWindow::on_BNdetailsCrl_clicked(void)
{
	if(crls)
		crls->showSelectedItems(crlView);
}
