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


#include "MainWindow.h"
#include "lib/load_obj.h"
#include "lib/pass_info.h"
#include <qapplication.h>
#include <qmenubar.h>
#include <qmessagebox.h>

void MainWindow::init_menu()
{
	QMenu *file, *help, *import;

	file = menuBar()->addMenu(tr("&File"));
	file->addAction(tr("New &DataBase"),  this,
				SLOT(new_database()), Qt::CTRL+Qt::Key_N );
	file->addAction(tr("Open &DataBase"),  this,
				SLOT(load_database()), Qt::CTRL+Qt::Key_L );
	acList += file->addAction(tr("&Close DataBase"), this,
				SLOT(close_database()), Qt::CTRL+Qt::Key_C );
	acList += file->addAction(tr("&Dump DataBase"), this,
				SLOT(dump_database()), Qt::CTRL+Qt::Key_D );
	acList += file->addAction(tr("&Import old db_dump"), this,
				SLOT(import_dbdump()), Qt::CTRL+Qt::Key_I );
	acList += file->addAction(tr("&Undelete items"), this,
				SLOT(undelete()), Qt::CTRL+Qt::Key_U );
	file->addSeparator();
	file->addAction(tr("E&xit"),  qApp, SLOT(quit()), Qt::ALT+Qt::Key_F4 );

	import = menuBar()->addMenu(tr("&Import"));
	import->addAction(tr("Keys"), this,
				SLOT(on_BNimportKey_clicked()) );
	import->addAction(tr("Requests"), this,
				SLOT(on_BNimportReq_clicked()) );
	import->addAction(tr("Certificates"), this,
				SLOT(on_BNimportCert_clicked()) );
	import->addAction(tr("PKCS#12"), this,
				SLOT(on_BNimportPKCS12_clicked()) );
	import->addAction(tr("PKCS#7"), this,
				SLOT(on_BNimportPKCS7_clicked()) );
	import->addAction(tr("Template"), this,
				SLOT(on_BNimportTemp_clicked()) );
	import->addAction(tr("Revocation list"), this,
				SLOT(on_BNimportCrl_clicked()) );
	import->addAction(tr("PEM file"), this,
				SLOT(loadPem()) );

	help = menuBar()->addMenu(tr("&Help") );
	help->addAction(tr("&Content"), this, SLOT(help()), Qt::Key_F1 );
	help->addAction(tr("&About"), this, SLOT(about()) );
	help->addAction(tr("Donations"), this, SLOT(donations()) );
	wdList += import;
}

void MainWindow::new_database()
{
	load_db l;
	QString fname = QFileDialog::getSaveFileName(this, l.caption, homedir,
			l.filter, 0, QFileDialog::DontConfirmOverwrite);

	if (fname.isEmpty())
		return;

	close_database();
	homedir = fname.mid(0, fname.lastIndexOf(QDir::separator()) );
	dbfile = fname;
	init_database();
}

void MainWindow::load_database()
{
	load_db l;
	QString fname = QFileDialog::getOpenFileName(this, l.caption, homedir,
			l.filter);

	if (fname.isEmpty())
		return;

	close_database();
	homedir = fname.mid(0, fname.lastIndexOf(QDir::separator()) );
	dbfile = fname;
	init_database();
}

void MainWindow::import_dbdump()
{
	extern int read_dump(const char *, db_base **, char *, int);
	char buf[50];

	db_base *dbl[] = { keys, reqs, certs, temps, crls };
	if (!keys)
		return;
	QString pass;
	QString file = QFileDialog::getOpenFileName(this, tr(XCA_TITLE), homedir,
			tr("Database dump ( *.dump );;All files ( *.* )"));

	if (file.isEmpty())
		return;

	pass_info p(tr("Import password"),
		tr("Please enter the password of the old database"), this);
	if (passRead(buf, 50, 0, &p) <0)
		return;
	pass = buf;
	try {
		read_dump(CCHAR(file), dbl, buf, 50);
		//printf("MD5:%s, r:%s\n", CCHAR(pki_key::md5passwd(CCHAR(pass))),buf);
		if (pki_key::md5passwd(CCHAR(pass)) != buf) {
			int ret = QMessageBox::warning(this, tr(XCA_TITLE),
				tr("Password verification error. Ignore keys ?"),
				tr("Import anyway"), tr("Cancel"));
			if (ret)
				return;
		}
		pki_key::setOldPasswd(CCHAR(pass));
		read_dump(CCHAR(file), dbl, NULL, 0);
		pki_key::eraseOldPasswd();
	} catch (errorEx &err) {
		Error(err);
	}
}
