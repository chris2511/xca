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
#include "PwDialog.h"
#include "lib/base.h"

#define NUM_PARAM 6
#define NUM_PARAM_LEAST 5

QString OpenDb::lastRemote;

DbMap OpenDb::getDatabases()
{
	QStringList list = QSqlDatabase::drivers();
	DbMap databases;

	databases["QPSQL7"]   = "PostgreSQL version 6 and 7";
	databases["QMYSQL3"]  = "MySQL 3.x and 4.x";
	//databases["QODBC3"]   = "Open Database Connectivity (ODBC)";

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

bool OpenDb::hasRemoteDrivers()
{
	return getDatabases().size() > 0;
}

DbMap OpenDb::splitRemoteDbName(QString db)
{
	static const char * const names[NUM_PARAM] =
		{ "all", "user", "host", "type", "dbname", "prefix" };
	DbMap map;
	QRegExp rx("(.*)@(.*)/(.*):([^#]*)#?([^#]*)");
	int i, pos = rx.indexIn(db);
	QStringList list = rx.capturedTexts();

	if (pos != -1 && list.size() >= NUM_PARAM_LEAST) {
		if (list.size() == NUM_PARAM_LEAST)
			list[NUM_PARAM_LEAST] = "";
		list[NUM_PARAM_LEAST] = list[NUM_PARAM_LEAST].toLower();
		for (i=0; i < NUM_PARAM; i++) {
			map[names[i]] = list[i];
		}
		qDebug() << "SPLIT DB:" << map;
	}
	return map;
}

bool OpenDb::isRemoteDB(QString db)
{
	DbMap remote_param = splitRemoteDbName(db);
	return remote_param.size() == NUM_PARAM;
}

void OpenDb::fillDbDropDown(QString current)
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

void OpenDb::setupDatabaseName(QString db)
{
	if (!isRemoteDB(db))
		return;

	DbMap remote_param = splitRemoteDbName(db);

	userName->setText(remote_param["user"]);
	hostName->setText(remote_param["host"]);
	dbName->setText(remote_param["dbname"]);
	prefix->setText(remote_param["prefix"]);
	fillDbDropDown(remote_param["type"]);
}

OpenDb::OpenDb(QWidget *parent, QString db)
	:QDialog(parent)
{
	setupUi(this);
	setWindowTitle(XCA_TITLE);
	fillDbDropDown();

	if (isRemoteDB(db)) {
		setupDatabaseName(db);
		sqlite = false;
		show_connection_settings = false;
	} else if (hasSqLite() && !db.isEmpty()) {
		dbName->setText(db);
		sqlite = true;
		show_connection_settings = false;
	} else {
		sqlite = false;
		show_connection_settings = true;
	}
}

QString OpenDb::getDbType() const
{
	qDebug() << "OpenDb::getDbType: "
		 << dbType->itemData(dbType->currentIndex()).toString();

	return sqlite ? hasSqLite() ? QString("QSQLITE") : QString("") :
			dbType->itemData(dbType->currentIndex()).toString();
}

void OpenDb::checkSqLite()
{
	if (hasSqLite())
		return;
	XCA_WARN(tr("No SqLite3 driver available. Please install the qt-sqlite package of your distribution"));
}

void OpenDb::openDatabase() const
{
	QString type = getDbType();
	QString pass = dbPassword->text();
	int round = 0;

	if (type.isEmpty()) {
		checkSqLite();
		return;
	}
	if (sqlite) {
		QFile f(dbName->text());
		if (!QFile::exists(dbName->text())) {
			f.open(QIODevice::WriteOnly);
			f.setPermissions(QFile::WriteOwner | QFile::ReadOwner);
			f.close();
		} else {
			QString msg = QString(
					"The file '%1' is not an XCA database")
					.arg(f.fileName());
			if (f.size() != 0) {
				f.open(QIODevice::ReadOnly);
				QByteArray ba = f.read(6);
				qDebug() << "FILE:" << f.fileName() << ba;
				if (ba != "SQLite") {
					XCA_WARN(msg);
					return;
				}
			}
		}
	}
	while (true) {
		QString connName = QSqlDatabase::addDatabase(type).connectionName();
		if (_openDatabase(connName, pass))
			break;

		if (pass.size() > 0 || round > 0)
			MainWindow::dbSqlError();

		Passwd pwd;
		pass_info p(XCA_TITLE,
			tr("Please enter the password to access the database server %2 as user '%1'.")
				.arg(userName->text()).arg(hostName->text()));
		QSqlDatabase::removeDatabase(connName);
		if (PwDialog::execute(&p, &pwd) != 1)
			break;
		pass = QString(pwd);
		round++;
	}
}

bool OpenDb::_openDatabase(QString connName, QString pass) const
{
	QSqlDatabase db = QSqlDatabase::database(connName, false);

	QStringList hostport = hostName->text().split(":");
	db.setDatabaseName(dbName->text());
	if (hostport.size() > 0)
		db.setHostName(hostport[0]);
	if (hostport.size() > 1)
		db.setPort(hostport[1].toInt());
	db.setUserName(userName->text());
	db.setPassword(pass);
	XSqlQuery::setTablePrefix(prefix->text().toLower());

	db.open();
	QSqlError e = db.lastError();
	if (!e.isValid() || e.type() != QSqlError::ConnectionError ||
			db.isOpen())
	{
		bool hasTrans = QSqlDatabase::database()
			.driver()->hasFeature(QSqlDriver::Transactions);
		DbTransaction::setHasTransaction(hasTrans);
		if (!hasTrans) {
			XCA_WARN(tr("The database driver does not support transactions. This may happen if the client and server have different versions. Continue with care."));
		}
		return true;
	}
	XSqlQuery::clearTablePrefix();
	db.close();
	return false;
};

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

void OpenDb::setLastRemote(QString db)
{
	if (isRemoteDB(db))
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
