/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __OPENDB_H
#define __OPENDB_H

#include "ui_OpenDb.h"
#include <QDialog>
#include <QSqlDatabase>

typedef QMap<QString, QString> DbMap;

class OpenDb: public QDialog, public Ui::OpenDb
{
	Q_OBJECT
    private:
	static DbMap getDatabases();
	static QString lastRemote;
	bool sqlite, show_connection_settings;
	bool _openDatabase(QString connName, QString pass) const;
	void setupDatabaseName(QString db);
	QString getDbType() const;
	void fillDbDropDown(QString current = QString());

    public:
	OpenDb(QWidget *parent, QString db);
	void openDatabase() const;
	QString getDescriptor() const;
	static bool hasSqLite();
	static void checkSqLite();
	static bool hasRemoteDrivers();
	static bool isRemoteDB(QString db);
	static DbMap splitRemoteDbName(QString db);
	static void setLastRemote(QString db);

    public slots:
	int exec();
};

#endif
