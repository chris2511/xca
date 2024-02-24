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
#include "Help.h"
#include "XcaWarning.h"
#include "lib/base.h"
#include "lib/dbhistory.h"

DbMap OpenDb::databases {
	{ "QPSQL",  "PostgreSQL" },
	{ "QMYSQL", "MySQL / MariaDB" },
	{ "QODBC",  "Open Database Connectivity (ODBC)" }
};

void OpenDb::initDatabases()
{
	QStringList list = QSqlDatabase::drivers();

	qDebug() << "SQL Plugins:" << list.join(",");;
	foreach (QString driver, databases.keys()) {
		if (!list.contains(driver))
			databases.take(driver);
		{
			QSqlDatabase db = QSqlDatabase::addDatabase(driver, driver + "_C");
			if (!db.isValid()) {
				qDebug() << "Database" << driver << "is Invalid";
				databases.take(driver);
			}
		}
		QSqlDatabase::removeDatabase(driver + "_C");
	}
	qDebug() << "Valid Remote DB Drivers: " << databases.size()
			<< "[" << databases.keys().join(",") << "]";
}

bool OpenDb::hasSqLite()
{
	return QSqlDatabase::isDriverAvailable("QSQLITE");
}

void OpenDb::driver_selected()
{
	if (getDbType() == "QODBC")
		dbName_label->setText("DSN");
	else
		dbName_label->setText(tr("Database name"));
}

bool OpenDb::hasRemoteDrivers()
{
	return databases.size() > 0;
}

void OpenDb::fillDbDropDown(const QString &current)
{
	dbType->clear();
	foreach(QString driver, databases.keys()) {
		dbType->insertItem(0, databases[driver], driver);
		if (driver == current)
			dbType->setCurrentIndex(0);
	}
	if (dbType->count() == 1) {
		dbType->setCurrentIndex(0);
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

	mainwin->helpdlg->register_ctxhelp_button(this, "remote_db");
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

int OpenDb::exec()
{
	if (!hasSqLite() && !hasRemoteDrivers())
		return 0;

	if (!show_connection_settings)
		return 1;

	setupDatabaseName(dbhistory::getLastRemote());

	bool ret = QDialog::exec();

	if (ret && !sqlite)
		dbhistory::setLastRemote(getDescriptor());
	return ret;
}
