/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QString>
#include <QDir>

#include "xfile.h"
#include "func.h"
#include "dbhistory.h"
#include "database_model.h"

QString dbhistory::lastRemote;

dbhistory::dbhistory()
{
	QString name;
	QSettings s = GlobalSettings();

	int size = s.beginReadArray("History");
	for (int i = 0; i < size; i++) {
		s.setArrayIndex(i);
		history << s.value("name").toString();
	}
	s.endArray();
	foreach(name, history) {
		if (database_model::isRemoteDB(name)) {
			setLastRemote(name);
			break;
		}
	}
}

void dbhistory::addEntry(const QString &name)
{
	int pos;
	QString fname = name;

	if (!database_model::isRemoteDB(fname))
		fname = relativePath(fname);

	pos = history.indexOf(fname);
	if (pos == 0)
		return; /* no changes */

	if (pos > 0)
		history.removeAt(pos);

	history.prepend(fname);
	while (history.size() > 10)
		history.removeLast();

	QSettings s = GlobalSettings();
	s.beginWriteArray("History");
	for (int i = 0; i < history.size(); i++) {
		s.setArrayIndex(i);
		s.setValue("name", history[i]);;
	}
	s.endArray();
}

void dbhistory::setLastRemote(const QString &db)
{
	if (database_model::isRemoteDB(db))
		lastRemote = db;
}

QString dbhistory::getLastRemote()
{
	return lastRemote;
}
