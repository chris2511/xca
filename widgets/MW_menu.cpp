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
#include "lib/load_obj.h"
#include <qapplication.h>
#include <qmenubar.h>
#include <qstatusbar.h>

void MainWindow::init_menu()
{
	QPopupMenu *file = new QPopupMenu( this );
	file->insertItem(tr("&Open default DataBase"),  this, SLOT(load_def_database()), CTRL+Key_O );
	file->insertItem(tr("Open &DataBase"),  this, SLOT(load_database()), CTRL+Key_L );
	file->insertItem(tr("&Close DataBase"), this, SLOT(close_database()), CTRL+Key_C );
	file->insertItem(tr("&Dump DataBase"), this, SLOT(dump_database()), CTRL+Key_C );
	file->insertSeparator();
	file->insertItem(tr("E&xit"),  qApp, SLOT(quit()), ALT+Key_F4 );

	QPopupMenu *help = new QPopupMenu( this );
	help->insertItem(tr("&Content"), this, SLOT(help()), Key_F1 );
	help->insertItem(tr("&About"), this, SLOT(about()) );
	
#if 0
	mb = new QMenuBar( this );
#endif
	mb = menuBar();
	mb->insertItem(tr("&File"), file );
	mb->insertSeparator();
	mb->insertItem(tr("&Help"), help );
	mb->setSeparator( QMenuBar::InWindowsStyle );

	statusBar()->message(XCA_TITLE);
}

void MainWindow::load_database()
{
	load_db l;
	QString fname;
	QFileDialog *dlg = new QFileDialog(this,0,true);
	dlg->setCaption(l.caption);
	dlg->setFilters(l.filter);
	dlg->setMode( QFileDialog::AnyFile );
	dlg->setDir(baseDir);
	if (dlg->exec()) {
		fname = dlg->selectedFile();
	}
	delete dlg;
	if (fname.isEmpty()) return;
	dbfile = fname;
	close_database();
	fprintf(stderr, "Dir: %s, File: %s\n", baseDir.latin1(),  dbfile.latin1() );
	emit init_database();
}

void MainWindow::load_def_database()
{
	dbfile = DBFILE;
	close_database();
    emit init_database();
}		
