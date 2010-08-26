/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_temp.h"
#include "func.h"
#include <widgets/NewX509.h>
#include <widgets/MainWindow.h>
#include <QtGui/QFileDialog>
#include <QtCore/QDir>
#include <QtGui/QContextMenuEvent>
#include <QtGui/QAction>
#include <QtGui/QInputDialog>
#include <QtGui/QMessageBox>

db_temp::db_temp(QString DBfile, MainWindow *mw)
	:db_x509name(DBfile, mw)
{
	allHeaders << new dbheader(HD_temp_type, true, tr("Type"));
	class_name = "templates";
	pkitype << tmpl;

	loadContainer();

	predefs = newPKI();
	QDir dir;
	if (!dir.cd(getPrefix()))
		return;
	dir.setFilter(QDir::Files | QDir::NoSymLinks);
	QFileInfoList list = dir.entryInfoList();
	load_temp l;
	pki_base *tmpl;
	for (int i = 0; i < list.size(); ++i) {
		QFileInfo fileInfo = list.at(i);
		QString name = getPrefix() + QDir::separator() +
				fileInfo.fileName();
		if (!name.endsWith(".xca", Qt::CaseInsensitive))
			continue;
		try {
			tmpl = l.loadItem(name);
			if (tmpl)
				predefs->append(tmpl);
		} catch(errorEx &err) {
			QMessageBox::warning(mainwin, tr(XCA_TITLE),
				tr("Bad template: %1").arg(name));
		}
	}
}

db_temp::~db_temp()
{
	delete predefs;
}

pki_base *db_temp::newPKI(db_header_t *)
{
	return new pki_temp("");
}

QStringList db_temp::getDescPredefs()
{
	QStringList x;
	x.clear();
	for(pki_temp *pki=(pki_temp*)predefs->iterate(); pki;
			pki=(pki_temp*)pki->iterate()) {
		x.append(QString("[default] ") + pki->getIntName());
	}
	x += getDesc();
	return x;
}

pki_base *db_temp::getByName(QString desc)
{
	if (!desc.startsWith("[default] "))
		return db_base::getByName(desc);
	desc.remove(0, 10); // "[default] "
	for(pki_temp *pki=(pki_temp*)predefs->iterate(); pki;
	            pki=(pki_temp*)pki->iterate()) {
		if (pki->getIntName() == desc)
			return pki;
	}
	return NULL;
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
	pki_temp *temp = NULL;
	QStringList sl;
	QString type;
	bool ok;
	int i, len;
	len = predefs->childCount();
	sl << tr("Nothing");
	for (i=0; i<len; i++) {
		sl << predefs->child(i)->getIntName();
	}
	type = QInputDialog::getItem(mainwin, tr(XCA_TITLE),
		tr("Preset Template values"), sl, 0, false, &ok, 0 );
	if (ok) {
		if (type == sl[0]) {
			temp = new pki_temp("");
		} else {
			for (i=0; i<len; i++) {
				pki_temp *t = (pki_temp *)predefs->child(i);
				if (type == t->getIntName()) {
					temp = new pki_temp(t);
					break;
				}
			}
		}
		if (!temp)
			return;
		temp->setIntName("--");
		if (runTempDlg(temp)) {
			insertPKI(temp);
			createSuccess(temp);
			return;
		}
	}
	delete temp;
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
		tr("XCA templates ( *.xca);; All files ( * )"));
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
	contextMenu(e, menu);
	currentIdx = QModelIndex();
	return;
}
