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
#include "MainWindow.h"
#include <qinputdialog.h>
#include <qfiledialog.h>
#include <qmessagebox.h>

#ifdef WIN32
#include <windows.h>
#endif

XcaListView::XcaListView( QWidget * parent = 0, 
		const char * name = 0, WFlags f = 0)
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

void XcaListView::loadCont()
{
	emit init_database();
	db->loadContainer();
	updateView();
}

pki_base *XcaListView::getSelected()
{
	emit init_database();
	QListViewItem *lvi = selectedItem();
	if (!lvi) return NULL;
	QString name = lvi->text(0);
	return db->getByName(name);
}

void XcaListView::showItem()
{
        showItem(getSelected(), false);
}

void XcaListView::showItem(QListViewItem *item)
{
        showItem(db->getByName(item->text(0)), false);
}

void XcaListView::rename(QListViewItem *item, int col, const QString &text)
{
	emit init_database();
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
}

void XcaListView::load_default(QStringList &filter, QString caption)
{
	filter.append( tr("All Files ( *.* )") );
        QString s = "";
        QStringList slist;
        QFileDialog *dlg = new QFileDialog(this,0,true);
        dlg->setCaption(caption);
        dlg->setFilters(filter);
        dlg->setMode( QFileDialog::ExistingFiles );
        dlg->setDir(MainWindow::getPath());
        if (dlg->exec()) {
                slist = dlg->selectedFiles();
		MainWindow::setPath(dlg->dirPath());
        }
        delete dlg;
        for ( QStringList::Iterator it = slist.begin(); it != slist.end(); ++it ) {
                s = *it;
                s = QDir::convertSeparators(s);
                try {
                        pki_base *item = loadItem(s);
                        insert(item);
                }
                catch (errorEx &err) {
                        Error(err);
                }
        }
}

void XcaListView::Error(errorEx &err)
{
	if (err.isEmpty()) {
		CERR("Empty error Exception silently ignored");
		return;
	}
	QMessageBox::warning(this,tr(XCA_TITLE), tr("The following error occured:") + "\n" +
			QString::fromLatin1(err.getCString()));
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
		updateViewItem(pki);
	}
}

void XcaListView::updateViewItem(pki_base *pki)
{
        if (! pki) return;
        QListViewItem *current = pki->getLvi();
        if (!current) return;
#ifdef qt3
	current->setRenameEnabled(0,true);
#endif
        current->setText(0, pki->getIntName());
}
							

pki_base *XcaListView::loadItem(QString) { CERR("Virtual called..."); return NULL; }
void XcaListView::newItem(void) { CERR("Virtual called..."); }
void XcaListView::deleteItem(void) { CERR("Virtual called..."); }
void XcaListView::load(void) { CERR("Virtual called..."); }
void XcaListView::store(void) { CERR("Virtual called..."); }
pki_base *XcaListView::insert(pki_base *) { CERR("Virtual called..."); return NULL; }
void XcaListView::popupMenu(QListViewItem *, QPoint const &, int) { CERR("Virtual called..."); }
void XcaListView::showItem(pki_base *, bool) { CERR("Virtual called...");}

QPixmap *XcaListView::loadImg(const char *name )
{
#ifdef WIN32
        static unsigned char PREFIX[100]="";
        if (PREFIX[0] == '\0') {
          LONG lRc;
      HKEY hKey;
      lRc=RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\xca",0,KEY_READ, &hKey);
      if(lRc!= ERROR_SUCCESS){
        // No key error
            QMessageBox::warning(NULL,tr(XCA_TITLE), "Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca' not found");
                PREFIX[0] = '\0';
          }
      else {
            ULONG dwLength = 100;
                lRc=RegQueryValueEx(hKey,"Install_Dir",NULL,NULL, PREFIX, &dwLength);
        if(lRc!= ERROR_SUCCESS){
            // No key error
                QMessageBox::warning(NULL,tr(XCA_TITLE), "Registry Key: 'HKEY_LOCAL_MACHINE->Software->xca->Install_Dir' not found");        
                    PREFIX[0] = '\0';
                }
          }
        lRc=RegCloseKey(hKey);
        }
#endif
        QString path = (char *)PREFIX;
        path += QDir::separator();
    return new QPixmap(path + name);
}
