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

bool OpenDb::hasRemoteDrivers()
{
	return getDatabases().size() > 0;
}

OpenDb::OpenDb(QWidget *parent, QString db)
	:QDialog(parent)
{
	DbMap databases;
	QString dbTypeName;

	setupUi(this);
	setWindowTitle(XCA_TITLE);

	QRegExp rx("(.*)@(.*)/(.*):(.*)");
	int pos = rx.indexIn(db);
	QStringList list = rx.capturedTexts();
	foreach(QString s, list)
		printf("OpenDB: '%s'\n", CCHAR(s));

	if (pos != -1 && list.size() == 5) {
		userName->setText(list[1]);
		hostName->setText(list[2]);
		dbTypeName = list[3];
		dbName->setText(list[4]);
		sqlite = false;
	} else {
		dbName->setText(db);
		sqlite = true;
	}

	databases = getDatabases();
	list = databases.keys();
	foreach (QString driver, list) {
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

	return sqlite ? QString("QSQLITE") :
			dbType->itemData(dbType->currentIndex()).toString();
}

void OpenDb::openDatabase() const
{
	QString type = getDbType();
	QString pass = dbPassword->text();

	if (sqlite && !QFile::exists(dbName->text())) {
		QFile f(dbName->text());
		f.open(QIODevice::WriteOnly);
		f.setPermissions(QFile::WriteOwner | QFile::ReadOwner);
		f.close();
	}
	while (true) {
		QString connName = QSqlDatabase::addDatabase(type).connectionName();
		if (_openDatabase(connName, pass))
			break;
		Passwd pwd;
		pass_info p(XCA_TITLE,
			tr("Please enter the password to access the database server %2 as user '%1'.")
				.arg(userName->text()).arg(hostName->text()));
		if (PwDialog::execute(&p, &pwd) != 1)
			break;
		pass = QString(pwd);
		QSqlDatabase::removeDatabase(connName);
	}
}

bool OpenDb::_openDatabase(QString connName, QString pass) const
{
	QSqlDatabase db = QSqlDatabase::database(connName, false);

	QStringList hostport = hostName->text().split(":");
	db.setDatabaseName(dbName->text());
	printf("hostport.size(): %d\n", hostport.size());
	if (hostport.size() > 0)
		db.setHostName(hostport[0]);
	if (hostport.size() > 1)
		db.setPort(hostport[1].toInt());

	db.setUserName(userName->text());
	db.setPassword(pass);

	db.open();
	QSqlError e = db.lastError();
	if (!e.isValid() || e.type() != QSqlError::ConnectionError ||
			sqlite || db.isOpen())
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
	if (sqlite)
		return 1;
	if (dbType->count() == 0)
		return 0;
	return QDialog::exec();
}
