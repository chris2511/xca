/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __OPENDB_H
#define __OPENDB_H

#include "ui_OpenDb.h"
#include <QSqlDatabase>

typedef QMap<QString, QString> DbMap;

class OpenDb: public QDialog, public Ui::OpenDb
{
	Q_OBJECT
    private:
	static DbMap getDatabases();
	bool sqlite;
	bool _openDatabase(QString connName, QString pass) const;
	QString getDbType() const;
	static DbMap splitRemoteDbName(QString db);

    public:
	OpenDb(QWidget *parent, QString db);
	void openDatabase() const;
	QString getDescriptor() const;
	static bool hasRemoteDrivers();
	static bool isRemoteDB(QString db);

    public slots:
	int exec();
};

#endif
