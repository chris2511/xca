/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_temp.h"
#include "func.h"
#include "widgets/XcaWarning.h"
#include "widgets/NewX509.h"
#include <QFileDialog>
#include <QDir>
#include <QContextMenuEvent>
#include <QAction>
#include <QInputDialog>
#include <QFileInfo>

db_temp::db_temp() : db_x509name("templates")
{
	sqlHashTable = "templates";
	pkitype << tmpl;

	updateHeaders();
	loadContainer();

	QDir dir;
	if (!dir.cd(getPrefix()))
		return;
	dir.setFilter(QDir::Files | QDir::NoSymLinks);
	QFileInfoList list = dir.entryInfoList();
	load_temp l;
	pki_temp *tmpl = new pki_temp(tr("Empty template"));
	tmpl->setAsPreDefined();
	predefs << tmpl;

	for (int i = 0; i < list.size(); ++i) {
		QFileInfo fileInfo = list.at(i);
		QString name = getPrefix() + "/" + fileInfo.fileName();
		if (!name.endsWith(".xca", Qt::CaseInsensitive))
			continue;
		try {
			tmpl = dynamic_cast<pki_temp*>(l.loadItem(name));
			if (tmpl) {
				tmpl->setAsPreDefined();
				predefs << tmpl;
			}
		} catch(errorEx &err) {
			XCA_WARN(tr("Bad template: %1")
				.arg(nativeSeparator(name)));
		}
	}
}

db_temp::~db_temp()
{
	qDeleteAll(predefs);
}

pki_base *db_temp::newPKI(enum pki_type type)
{
	(void)type;
	return new pki_temp("");
}

QList<pki_temp *> db_temp::getPredefs() const
{
	return predefs;
}

bool db_temp::alterTemp(pki_temp *temp)
{
	XSqlQuery q;
	QSqlError e;

	Transaction;
	if (!TransBegin())
		return false;
	SQL_PREPARE(q, "UPDATE templates SET version=?, template=? WHERE item=?");
	q.bindValue(0, TMPL_VERSION);
	q.bindValue(1, temp->toB64Data());
	q.bindValue(2, temp->getSqlItemId());
	q.exec();
	e = q.lastError();
	XCA_SQLERROR(e);
	if (e.isValid()) {
		TransRollback();
		return false;
	}
	updateItem(temp, temp->getIntName(), temp->getComment());
	TransCommit();
	return true;
}

void db_temp::load()
{
	load_temp l;
	load_default(l);
}

void db_temp::store(QModelIndex index)
{
	pki_temp *temp = fromIndex<pki_temp>(index);

	if (!index.isValid() || !temp)
		return;

	QString fn = Settings["workingdir"] +
		temp->getUnderlinedName() + ".xca";
	QString s = QFileDialog::getSaveFileName(NULL,
		tr("Save template as"),	fn,
		tr("XCA templates ( *.xca );; All files ( * )"));
	if (s.isEmpty())
		return;

	update_workingdir(s);
	try {
		XFile file(s);
		file.open_key();
		temp->writeTemp(file);
	}
	catch (errorEx &err) {
		XCA_ERROR(err);
	}
}
