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
#include "lib/load_obj.h"
#include <Qt/qapplication.h>
#include <Qt/qmenubar.h>

void MainWindow::init_menu()
{
	QMenu *file;
	QMenu *help;

	file = menuBar()->addMenu(tr("&File"));
	file->addAction(tr("&Open default DataBase"),  this,
				SLOT(load_def_database()), Qt::CTRL+Qt::Key_O );
	file->addAction(tr("Open &DataBase"),  this,
				SLOT(load_database()), Qt::CTRL+Qt::Key_L );
	file->addAction(tr("&Close DataBase"), this,
				SLOT(close_database()), Qt::CTRL+Qt::Key_C );
	file->addAction(tr("&Dump DataBase"), this,
				SLOT(dump_database()), Qt::CTRL+Qt::Key_C );
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
	dlg->setDirectory(getPath());
	if (dlg->exec()) {
		fname = dlg->selectedFiles()[0];
		setPath(dlg->directory().path());
	}
	delete dlg;
	if (fname.isEmpty())
		return;
	dbfile = fname;
	close_database();
	fprintf(stderr, "Dir: %s, File: %s\n", CCHAR(baseDir),  CCHAR(dbfile));
	init_database();
}

void MainWindow::load_def_database()
{
	dbfile = DBFILE;
	close_database();
    init_database();
}
