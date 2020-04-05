/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QString>
#include <QDir>

#include "widgets/OpenDb.h"
#include "xfile.h"
#include "func.h"
#include "dbhistory.h"
#include "database_model.h"

static QString dbhistory_file()
{
	return getUserSettingsDir() +  "/dbhistory";
}

dbhistory::dbhistory()
{
	QString name;
	XFile file(dbhistory_file());

	try {
		file.open_read();
	} catch (...) {
		return;
	}

	history.clear();
	while (!file.atEnd()) {
		char buf[1024];
		ssize_t size = file.readLine(buf, sizeof buf);
		if (size <= 0)
			break;
		name = QString::fromUtf8(buf).trimmed();
		if (name.size() == 0)
			continue;
		if (history.indexOf(name) == -1)
			history << name;
	}
	file.close();

	foreach(name, history) {
		if (database_model::isRemoteDB(name)) {
			OpenDb::setLastRemote(name);
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

	XFile file(dbhistory_file());
	if (!file.open_write())
		return;

	QString all = history.join("\n");
	if (file.write(all.toUtf8()) <= 0)
		qDebug() << "Error writing history" << file.fileName()
			 << file.errorString();
	file.close();
}

