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



#include "XcaListView.h"
#include "widgets/MainWindow.h"
#include "widgets/ImportMulti.h"
#include <qinputdialog.h>
#include <qfiledialog.h>
#include <qmessagebox.h>

XcaListView::XcaListView( QWidget * parent, const char * name, WFlags f)
		:QListView(parent, name, f)
{
#ifdef qt3      
	connect( this, SIGNAL(itemRenamed(QListViewItem *, int, const QString &)),
	  this, SLOT(rename(QListViewItem *, int, const QString &)));
#endif		
	connect( this, SIGNAL(rightButtonPressed(QListViewItem *, const QPoint &, int)),
	  this, SLOT(popupMenu(QListViewItem *, const QPoint &, int))) ;
	
	connect( this, SIGNAL(doubleClicked(QListViewItem *)),
	  this, SLOT(showItem(QListViewItem *))) ;
}

void XcaListView::setDB(db_base *mydb)
{
	db = mydb;
	updateView();
}

void XcaListView::rmDB(db_base *mydb)
{
	db = NULL;
	clear();
}

void XcaListView::loadCont()
{
	CHECK_DB
	db->loadContainer();
	updateView();
}

pki_base *XcaListView::getSelected()
{
	CHECK_DB_NULL
	QListViewItem *lvi = selectedItem();
	if (!lvi) return NULL;
	QString name = lvi->text(0);
	return db->getByName(name);
}

void XcaListView::showItem()
{
	showItem(getSelected(), false);
}

void XcaListView::showItem(QString name)
{
	showItem(db->getByName(name), false);
}

void XcaListView::showItem(QListViewItem *item)
{
	showItem(db->getByName(item->text(0)), false);
}

void XcaListView::rename(QListViewItem *item, int col, const QString &text)
{
	CHECK_DB
	try {
		pki_base *pki = db->getByPtr(item);
		db->renamePKI(pki, text);
	}
	catch (errorEx &err) {
		Error(err);
	}
}

void XcaListView::startRename()
{
	CHECK_DB
	try {
#ifdef qt3
		QListViewItem *item = selectedItem();
		if (item == NULL) return;
		item->startRename(0);
#else
		renameDialog();
#endif
	}
	catch (errorEx &err) {
		Error(err);
	}
}

void XcaListView::renameDialog()
{
        pki_base * pki = getSelected();
        if (!pki) return;
        QString name= pki->getIntName();
        bool ok;
        QString nname = QInputDialog::getText (XCA_TITLE, "Please enter the new name",
                        QLineEdit::Normal, name, &ok, this );
        if (ok && name != nname) {
                db->renamePKI(pki, nname);
		pki->getLvi()->setText(0, pki->getIntName());
						   
        }
}

void XcaListView::deleteItem_default(QString t1, QString t2)
{
	pki_base *del = getSelected();
	if (!del) return;
	if (QMessageBox::information(this,tr(XCA_TITLE),
		t1 + ": '" + del->getIntName() + "'\n" + t2,
		tr("Delete"), tr("Cancel"))
        ) return;
	try {
		db->deletePKI(del);
	}
	catch (errorEx &err) {
		Error(err);
	}
	updateView();
}

void XcaListView::load_default(load_base &load)
{
	QStringList slist;
	
	QFileDialog *dlg = new QFileDialog(this,0,true);
	CHECK_DB
	
	dlg->setCaption(load.caption);
	dlg->setFilters(load.filter);
	dlg->setMode( QFileDialog::ExistingFiles );
	dlg->setDir(MainWindow::getPath());
	if (dlg->exec()) {
		slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
	}
	delete dlg;

	ImportMulti *dlgi = NULL;
	dlgi = new ImportMulti(this, NULL, true);
	for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
		QString s = *it;
		s = QDir::convertSeparators(s);
		pki_base *item = NULL;
		try {
			item = load.loadItem(s);
		}
		catch (errorEx &err) {
			Error(err);
			if (item) {
				delete item;
				item = NULL;
			}
		}
		dlgi->addItem(item);
	}
	dlgi->execute();
	delete dlgi;
	updateView();
}

void XcaListView::Error(errorEx &err)
{
	MainWindow::Error(err);
}

bool XcaListView::Error(pki_base *pki)
{
	if (!pki) {
		QMessageBox::warning(this,tr(XCA_TITLE), tr("The system detected a NULL pointer, maybe the system is out of memory" ));
		qFatal("NULL pointer detected - Exiting");
	}
	
	return false;
}

void XcaListView::updateView()
{
	CHECK_DB
	clear();
	QList<pki_base> container;
	pki_base *pki;
	container = db->getContainer();
	if (container.isEmpty()) return;
	for ( pki = container.first(); pki != NULL; pki = container.next() ) pki->delLvi();
        QListIterator<pki_base> it(container);
        for ( ; it.current(); ++it ) {
                pki = it.current();
		QListViewItem *lvi = new QListViewItem(this, pki->getIntName());
		insertItem(lvi);
		pki->setLvi(lvi);
		pki->updateView();
	}
}

void XcaListView::newItem(void) { }
void XcaListView::deleteItem(void) { }
void XcaListView::load(void) { }
void XcaListView::store(void) { }
void XcaListView::popupMenu(QListViewItem *, QPoint const &, int) { }
void XcaListView::showItem(pki_base *, bool) { }

