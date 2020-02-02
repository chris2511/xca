/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __OPENDB_H
#define __OPENDB_H

#include "lib/database_model.h"

#include "ui_OpenDb.h"
#include <QDialog>
#include <QSqlDatabase>

class OpenDb: public QDialog, public Ui::OpenDb
{
	Q_OBJECT
    private:
	static DbMap getDatabases();
	static QString lastRemote;
	bool sqlite, show_connection_settings;
	void setupDatabaseName(const QString &db);
	QString getDbType() const;
	void fillDbDropDown(const QString &current);

    public:
	OpenDb(QWidget *parent, const QString &db);
	QString getDescriptor() const;
	static bool hasSqLite();
	static void checkSqLite();
	static bool hasRemoteDrivers();
	static void setLastRemote(const QString &db);

    public slots:
	int exec();
	void driver_selected();
};

#endif
