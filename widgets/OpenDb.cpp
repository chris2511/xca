/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <stdio.h>
#include <QStringList>
#include <QFile>

#include "OpenDb.h"
#include "PwDialog.h"
#include "lib/base.h"

OpenDb::OpenDb(QWidget *parent, QString db)
	:QDialog(parent)
{
	QMap<QString, QString> databases;
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
	} else {
		dbName->setText(db);
		dbTypeName = "QSQLITE";
	}

	databases["QPSQL7"]   = "PostgreSQL version 6 and 7";
	databases["QMYSQL3"]  = "MySQL 3.x and 4.x";
	databases["QSQLITE" ] = "SQLite version 3 or above";

	list = QSqlDatabase::drivers();
	foreach (QString driver, list) {
		if (!databases.contains(driver))
			continue;
		dbType->insertItem(0, databases[driver], driver);
		if (driver == dbTypeName)
			dbType->setCurrentIndex(0);
	}
}

void OpenDb::openDatabase() const
{
	QString type = dbType->itemData(dbType->currentIndex()).toString();
	QString pass = dbPassword->text();

	if (type == "QSQLITE" && !QFile::exists(dbName->text())) {
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
		pass =QString(pwd);
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
			db.driverName() == "QSQLITE" || db.isOpen())
		return true;

	db.close();
	return false;
};

QString OpenDb::getDescriptor() const
{
	QString type = dbType->itemData(dbType->currentIndex()).toString();
	if (type == "QSQLITE")
		return dbName->text();

	return QString("%1@%2/%3:%4")
			.arg(userName->text())
			.arg(hostName->text())
			.arg(type)
			.arg(dbName->text());
}

int OpenDb::exec()
{
	QString type = dbType->itemData(dbType->currentIndex()).toString();
	if (type != "QSQLITE")
		return QDialog::exec();
	return 1;
}
