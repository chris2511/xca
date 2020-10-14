/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <stdio.h>
#include <QStringList>
#include <QDebug>
#include <QFile>

#include "MainWindow.h"
#include "OpenDb.h"
#include "XcaWarning.h"
#include "lib/base.h"

QString OpenDb::lastRemote;

DbMap OpenDb::getDatabases()
{
	QStringList list = QSqlDatabase::drivers();
	DbMap databases;

	databases["QPSQL7"]   = "PostgreSQL";
	databases["QMYSQL3"]  = "MySQL / MariaDB";
	databases["QODBC3"]   = "Open Database Connectivity (ODBC)";

	foreach (QString driver, databases.keys()) {
		if (!list.contains(driver))
			databases.take(driver);
	}
	qDebug() << "Available Remote DB Drivers: " << databases.size();
	foreach (QString driver, databases.keys())
		qDebug() << driver;

	return databases;
}

bool OpenDb::hasSqLite()
{
	return QSqlDatabase::isDriverAvailable("QSQLITE");
}

void OpenDb::driver_selected()
{
	if (getDbType() == "QODBC3")
		dbName_label->setText("DSN");
	else
		dbName_label->setText(tr("Database name"));
}

bool OpenDb::hasRemoteDrivers()
{
	return getDatabases().size() > 0;
}

void OpenDb::fillDbDropDown(const QString &current)
{
	DbMap databases = getDatabases();
	dbType->clear();
	foreach(QString driver, databases.keys()) {
		dbType->insertItem(0, databases[driver], driver);
		if (driver == current)
			dbType->setCurrentIndex(0);
	}
	if (dbType->count() == 1) {
		dbType->setCurrentIndex(0);
		dbType->setEnabled(false);
	}
}

void OpenDb::setupDatabaseName(const QString &db)
{
	if (!database_model::isRemoteDB(db))
		return;

	DbMap remote_param = database_model::splitRemoteDbName(db);

	userName->setText(remote_param["user"]);
	hostName->setText(remote_param["host"]);
	dbName->setText(remote_param["dbname"]);
	prefix->setText(remote_param["prefix"]);
	fillDbDropDown(remote_param["type"]);
}

OpenDb::OpenDb(QWidget *parent, const QString &db)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	fillDbDropDown(QString());

	if (database_model::isRemoteDB(db)) {
		setupDatabaseName(db);
		sqlite = false;
		show_connection_settings = true;
	} else if (hasSqLite() && !db.isEmpty()) {
		dbName->setText(db);
		sqlite = true;
		show_connection_settings = false;
	} else {
		sqlite = false;
		show_connection_settings = true;
	}
	driver_selected();
	connect(dbType, SIGNAL(currentIndexChanged(int)),
		this, SLOT(driver_selected()));
}

QString OpenDb::getDbType() const
{
	return sqlite ? hasSqLite() ? QString("QSQLITE") : QString("") :
			dbType->itemData(dbType->currentIndex()).toString();
}

void OpenDb::checkSqLite()
{
	if (hasSqLite())
		return;
	XCA_WARN(tr("No SqLite3 driver available. Please install the qt-sqlite package of your distribution"));
}

QString OpenDb::getDescriptor() const
{
	QString pref = prefix->text();
	if (!pref.isEmpty())
		pref = QString("#%1").arg(pref.toLower());
	return sqlite ?
		dbName->text() :
		QString("%1@%2/%3:%4%5")
			.arg(userName->text())
			.arg(hostName->text())
			.arg(getDbType())
			.arg(dbName->text())
			.arg(pref);
}

void OpenDb::setLastRemote(const QString &db)
{
	if (database_model::isRemoteDB(db))
		lastRemote = db;
}

int OpenDb::exec()
{
	if (!hasSqLite() && !hasRemoteDrivers())
		return 0;

	if (!show_connection_settings)
		return 1;

	setupDatabaseName(lastRemote);

	bool ret = QDialog::exec();

	if (ret && !sqlite)
		lastRemote = getDescriptor();
	return ret;
}
