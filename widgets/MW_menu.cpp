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
#include <Qt/qapplication.h>
#include <Qt/qmenubar.h>
#include <Qt/qmessagebox.h>

void MainWindow::init_menu()
{
	QMenu *file;
	QMenu *help;

	file = menuBar()->addMenu(tr("&File"));
	file->addAction(tr("Open &DataBase"),  this,
				SLOT(load_database()), Qt::CTRL+Qt::Key_L );
	file->addAction(tr("&Close DataBase"), this,
				SLOT(close_database()), Qt::CTRL+Qt::Key_C );
	file->addAction(tr("&Dump DataBase"), this,
				SLOT(dump_database()), Qt::CTRL+Qt::Key_D );
	file->addAction(tr("&Import old db_dump"), this,
				SLOT(import_dbdump()), Qt::CTRL+Qt::Key_I );
	file->addSeparator();
	file->addAction(tr("E&xit"),  qApp, SLOT(quit()), Qt::ALT+Qt::Key_F4 );

	help = menuBar()->addMenu(tr("&Help") );
	help->addAction(tr("&Content"), this, SLOT(help()), Qt::Key_F1 );
	help->addAction(tr("&About"), this, SLOT(about()) );
}

void MainWindow::load_database()
{
	load_db l;
	QString fname;
	QFileDialog *dlg = new QFileDialog(this);
	dlg->setWindowTitle(l.caption);
	dlg->setFilters(l.filter);
	dlg->setFileMode( QFileDialog::AnyFile );
	dlg->setDirectory(workingdir);
	if (dlg->exec()) {
		fname = dlg->selectedFiles()[0];
	}
	delete dlg;
	if (fname.isEmpty())
		return;
	dbfile = fname;
	close_database();
	init_database();
}

void MainWindow::import_dbdump()
{
	extern int read_dump(const char *filename, db_base **dbs, char*buf);
	char buf[50];

	db_base *dbl[] = { keys, reqs, certs, temps, crls };
	if (!keys)
		return;
	QStringList filt;
	QString file, pass;
	load_db l;
	QFileDialog *dlg = new QFileDialog(this);
	dlg->setWindowTitle(l.caption);
	dlg->setFilters(l.filter);
	dlg->setFileMode( QFileDialog::ExistingFile );
	dlg->setDirectory(getPath());
	if (dlg->exec()) {
		if (!dlg->selectedFiles().isEmpty())
			file = dlg->selectedFiles()[0];
	}
	pass_info p(tr("New Password"),
		tr("Please enter the password of the old database"));
	if (passRead(buf, 50, 0, &p) <0)
		return;
	pass = buf;
	try {
		read_dump(CCHAR(file), dbl, buf);
		printf("MD5:%s, r:%s\n", CCHAR(pki_key::md5passwd(CCHAR(pass))),buf);
		if (pki_key::md5passwd("pass") != buf) {
			int ret = QMessageBox::warning(this, tr(XCA_TITLE),
				tr("Password verification error. Ignore keys ?"),
				tr("Import anyway"), tr("Cancel"));
			if (ret)
				return;
		}
		read_dump(CCHAR(file), dbl, NULL);
	} catch (errorEx &err) {
		Error(err);
	}
}
