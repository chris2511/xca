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

DbMap OpenDb::getDatabases()
{
	QStringList list = QSqlDatabase::drivers();
	DbMap databases;

	databases["QPSQL7"]   = "PostgreSQL version 6 and 7";
	databases["QMYSQL3"]  = "MySQL 3.x and 4.x";

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
	static const char * const names[] =
		{ "all", "user", "host", "type", "dbname" };
	DbMap map;
	QRegExp rx("(.*)@(.*)/(.*):(.*)");
	int i, pos = rx.indexIn(db);
	QStringList list = rx.capturedTexts();

	if (pos != -1 && list.size() == 5) {
		for (i=0; i<5; i++) {
			qDebug() << "OpenDB: " << names[i] << list[i];
			map[names[i]] = list[i];
		}
	}
	return map;
}

bool OpenDb::isRemoteDB(QString db)
{
	DbMap remote_param = splitRemoteDbName(db);
	return remote_param.size() == 5;
}

OpenDb::OpenDb(QWidget *parent, QString db)
	:QDialog(parent)
{
	DbMap databases, remote_param;
	QString dbTypeName;

	setupUi(this);
	setWindowTitle(XCA_TITLE);

	remote_param = splitRemoteDbName(db);
	if (remote_param.size() == 5) {
		userName->setText(remote_param["user"]);
		hostName->setText(remote_param["host"]);
		dbTypeName = remote_param["type"];
		dbName->setText(remote_param["dbname"]);
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
	databases = getDatabases();
	foreach (QString driver, databases.keys()) {
		dbType->insertItem(0, databases[driver], driver);
		if (driver == dbTypeName)
			dbType->setCurrentIndex(0);
	}
	if (dbType->count() == 1) {
		dbType->setCurrentIndex(0);
		dbType->setEnabled(false);
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

	db.open();
	QSqlError e = db.lastError();
	if (!e.isValid() || e.type() != QSqlError::ConnectionError ||
			db.isOpen())
		return true;

	db.close();
	return false;
};

QString OpenDb::getDescriptor() const
{
	return sqlite ?
		dbName->text() :
		QString("%1@%2/%3:%4")
			.arg(userName->text())
			.arg(hostName->text())
			.arg(getDbType())
			.arg(dbName->text());
}

int OpenDb::exec()
{
	if (dbType->count() == 0)
		return 0;
	if (!show_connection_settings)
		return 1;
	return QDialog::exec();
}
