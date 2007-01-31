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


#include "db_temp.h"
#include <widgets/NewX509.h>
#include <widgets/MainWindow.h>
#include <Qt/qfiledialog.h>
#include <Qt/qdir.h>
#include <Qt/qevent.h>
#include <Qt/qaction.h>

db_temp::db_temp(QString DBfile, MainWindow *mw)
	:db_base(DBfile, mw)
{
	delete rootItem;
	rootItem = newPKI();
	headertext << "Name" << "Type";
	delete_txt = tr("Delete the Template(s)");
	view = mw->tempView;
	class_name = "templates";
	loadContainer();
}

pki_base *db_temp::newPKI(){
	return new pki_temp("");
}

bool db_temp::runTempDlg(pki_temp *temp)
{
	NewX509 *dlg = new NewX509(mainwin);
	emit connNewX509(dlg);

	dlg->setTemp(temp);
	dlg->fromTemplate(temp);
	if (!dlg->exec()) {
		delete dlg;
		return false;
	}
	dlg->toTemplate(temp);
	delete dlg;
	return true;
}

void db_temp::newItem()
{
	pki_temp *temp = new pki_temp("--");
	if (runTempDlg(temp)) {
		insertPKI(temp);
	}
	else {
		delete temp;
	}
}

void db_temp::changeTemp()
{
	if (!currentIdx.isValid())
		return;
	pki_temp *temp = static_cast<pki_temp*>(currentIdx.internalPointer());
	alterTemp(temp);
}

void db_temp::duplicateTemp()
{
	if (!currentIdx.isValid())
		return;
	pki_temp *temp = static_cast<pki_temp*>(currentIdx.internalPointer());
	pki_temp *newtemp = new pki_temp(temp);
	newtemp->setIntName(newtemp->getIntName() + " " + tr("copy"));
	insertPKI(newtemp);
}

bool db_temp::alterTemp(pki_temp *temp)
{
	if (!runTempDlg(temp))
		return false;
	updatePKI(temp);
	return true;
}

void db_temp::showPki(pki_base *pki)
{
	alterTemp((pki_temp *)pki);
}

void db_temp::load()
{
	load_temp l;
	load_default(l);
}

void db_temp::store()
{
	if (!currentIdx.isValid())
		return;
	pki_temp *temp = static_cast<pki_temp*>(currentIdx.internalPointer());

	QString fn = mainwin->getPath() + QDir::separator() +
		temp->getUnderlinedName() + ".xca";
	QString s = QFileDialog::getSaveFileName(mainwin,
		tr("Save template as"),	fn,
		tr("XCA templates ( *.xca);; All files ( *.* )"));
	if (s.isEmpty())
		return;
	s = QDir::convertSeparators(s);
	mainwin->setPath(s.mid(0, s.lastIndexOf(QRegExp("[/\\\\]")) ));
	try {
		temp->writeTemp(s);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
}

void db_temp::certFromTemp()
{
	if (!currentIdx.isValid())
		return;
	pki_temp *temp = static_cast<pki_temp*>(currentIdx.internalPointer());
	emit newCert(temp);
}

void db_temp::reqFromTemp()
{
	if (!currentIdx.isValid())
		return;
	pki_temp *temp = static_cast<pki_temp*>(currentIdx.internalPointer());
	emit newReq(temp);
}

void db_temp::alterTemp()
{
	if (!currentIdx.isValid())
		return;
	pki_temp *temp = static_cast<pki_temp*>(currentIdx.internalPointer());
	alterTemp(temp);
}

void db_temp::showContextMenu(QContextMenuEvent *e, const QModelIndex &index)
{
	QMenu *menu = new QMenu(mainwin);
	currentIdx = index;

	menu->addAction(tr("New Template"), this, SLOT(newItem()));
	menu->addAction(tr("Import"), this, SLOT(load()));
	if (index != QModelIndex()) {
		menu->addAction(tr("Rename"), this, SLOT(edit()));
		menu->addAction(tr("Export"), this, SLOT(store()));
		menu->addAction(tr("Change"), this, SLOT(alterTemp()));
		menu->addAction(tr("Delete"), this, SLOT(delete_ask()));
		menu->addAction(tr("Duplicate"), this, SLOT(duplicateTemp()));
		menu->addAction(tr("Create certificate"), this,
				SLOT(certFromTemp()));
		menu->addAction(tr("Create request"), this, SLOT(reqFromTemp()));
	}
	menu->exec(e->globalPos());
	delete menu;
	currentIdx = QModelIndex();
	return;
}
