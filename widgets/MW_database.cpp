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
#include "lib/exception.h"
#include <Qt/qdir.h>
#include <Qt/qstatusbar.h>

void MainWindow::init_database()
{
	fprintf(stderr, "Opening database: %s\n", CCHAR(dbfile));
	keys = NULL; reqs = NULL; certs = NULL; temps = NULL; crls = NULL;

	certView->setRootIsDecorated(db_x509::treeview);

	try {
		initPass();
		keys = new db_key(dbfile, this);
		reqs = new db_x509req(dbfile, this);
		certs = new db_x509(dbfile, this);
		temps = new db_temp(dbfile, this);
		crls = new db_crl(dbfile, this);
	}
	catch (errorEx &err) {
		Error(err);
		return;
	}

	connect( keys, SIGNAL(newKey(pki_key *)),
		certs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		certs, SLOT(delKey(pki_key *)) );
	connect( keys, SIGNAL(newKey(pki_key *)),
		reqs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		reqs, SLOT(delKey(pki_key *)) );

	connect( certs, SIGNAL(connNewX509(NewX509 *)), this,
		SLOT(connNewX509(NewX509 *)) );
	connect( reqs, SIGNAL(connNewX509(NewX509 *)), this,
		SLOT(connNewX509(NewX509 *)) );

	connect( reqs, SIGNAL(newCert(pki_x509req *)),
		certs, SLOT(newCert(pki_x509req *)) );
	connect( certs, SIGNAL(genCrl(pki_x509 *)),
		crls, SLOT(newItem(pki_x509 *)) );
	connect( temps, SIGNAL(newCert(pki_temp *)),
		certs, SLOT(newCert(pki_temp *)) );
	connect( temps, SIGNAL(newReq(pki_temp *)),
		reqs, SLOT(newItem(pki_temp *)) );

	statusBar()->showMessage(tr("Database") + ":" + dbfile);

	keyView->setIconSize(pki_key::icon[0]->size());
	reqView->setIconSize(pki_x509req::icon[0]->size());
	certView->setIconSize(pki_x509::icon[0]->size());
	tempView->setIconSize(pki_temp::icon->size());
	crlView->setIconSize(pki_crl::icon->size());

	keyView->setModel(keys);
	reqView->setModel(reqs);
	certView->setModel(certs);
	tempView->setModel(temps);
	crlView->setModel(crls);

	try {
		db mydb(dbfile);
		char *p;
		if (!mydb.find(setting, "workingdir")) {
			if ((p = (char *)mydb.load(NULL))) {
				workingdir = p;
				free(p);
			}
		}
	} catch (errorEx &err) {
		Error(err);
		return;
	}
	setWindowTitle(tr(XCA_TITLE));
}

void MainWindow::dump_database()
{
	QString dirname;

	QFileDialog *dlg = new QFileDialog(this);
	dlg->setWindowTitle(tr("Dump to directory"));
	dlg->setFileMode(QFileDialog::DirectoryOnly);
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

	printf("Dumping to %s\n", CCHAR(dirname));
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

	if (crls)
		delete(crls);
	if (reqs)
		delete(reqs);
	if (certs)
		delete(certs);
	if (temps)
		delete(temps);
	if (keys)
		delete(keys);

	reqs = NULL;
	certs = NULL;
	temps = NULL;
	keys = NULL;
	settings = NULL;

	pki_key::erasePasswd();

	if (!crls)
		return;
	crls = NULL;

	try {
		db mydb(dbfile);
		mydb.shrink( DBFLAG_OUTDATED | DBFLAG_DELETED );
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
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

void MainWindow::on_keyView_doubleClicked(const QModelIndex &m)
{
	if (keys)
		keys->showItem(keyView->getIndex(m));
}

void MainWindow::on_reqView_doubleClicked(const QModelIndex &m)
{
	if (reqs)
		reqs->showItem(reqView->getIndex(m));
}

void MainWindow::on_certView_doubleClicked(const QModelIndex &m)
{
	if (certs)
		certs->showItem(certView->getIndex(m));
}

void MainWindow::on_tempView_doubleClicked(const QModelIndex &m)
{
	if (temps)
		temps->showItem(tempView->getIndex(m));
}

void MainWindow::on_crlView_doubleClicked(const QModelIndex &m)
{
	if (crls)
		crls->showItem(crlView->getIndex(m));
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

void MainWindow::on_BNviewState_clicked(void)
{
	if(certs)
		certs->changeView();
	 certView->setRootIsDecorated(db_x509::treeview);
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
void MainWindow::on_BNnewTemp_clicked(void)
{
	if (temps)
		temps->newItem();
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
void MainWindow::on_BNexportCrl_clicked(void)
{
	if (crls)
		crls->storeSelectedItems(crlView);
}
void MainWindow::on_BNdetailsCrl_clicked(void)
{
	if(crls)
		crls->showSelectedItems(crlView);
}
