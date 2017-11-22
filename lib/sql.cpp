/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include <QString>
#include <QDebug>
#include "base.h"
#include "sql.h"

int DbTransaction::mutex;
int DbTransaction::error;

void DbTransaction::debug(const char *func, const char *file, int line)
{
	QString f = file;
	qDebug() << QString("%1(%2) Transaction: %3 Level %4, E:%5 ")
			.arg(file + QString(file).lastIndexOf("/") +1)
			.arg(line).arg(func).arg(mutex).arg(error);
}

DbTransaction::DbTransaction()
{
	has_begun = false;
}

DbTransaction::~DbTransaction()
{
	if (has_begun)
		rollback("Destructor", 0);
}

bool DbTransaction::begin(const char *file, int line)
{
	mutex++;
	has_begun = true;
	debug("Begin", file, line);
	return mutex > 1 ? true : QSqlDatabase::database().transaction();
}

bool DbTransaction::finish(const char *oper, const char *file, int line)
{
	if (!has_begun)
		return true;
	if (mutex > 0)
		mutex--;
	else
		qCritical() << "Unbalanced DB Transaction in " << oper;
	debug(oper, file, line);
	has_begun = false;
	if (mutex > 0)
		return true;

	QSqlDatabase db = QSqlDatabase::database();
	int e = error;
	error = 0;
	return e ? db.rollback() : db.commit();
}

bool DbTransaction::commit(const char *file, int line)
{
	return finish("Commit", file, line);
}

bool DbTransaction::rollback(const char *file, int line)
{
	error++;
	return finish("Rollback", file, line);
}

bool DbTransaction::done(QSqlError e, const char *file, int line)
{
	return e.isValid() ? rollback(file, line) : commit(file, line);
}


QString XSqlQuery::query_details()
{
	QString lq = lastq;
	QList<QVariant> list = boundValues().values();
	QStringList sl;
	for (int i = 0; i < list.size(); ++i)
		sl << list.at(i).toString();
	if (sl.size())
		lq += QString("[%1]").arg(sl.join(", "));
	return QString("%1:%2 (%3)").arg(file).arg(line).arg(lq);
}

QSqlError XSqlQuery::lastError()
{
	QSqlError e = QSqlQuery::lastError();
	if (!e.isValid())
		return e;
	QString dt = e.driverText();
	e.setDriverText(QString("%1 - %2").arg(dt).arg(query_details()));
	return e;
}

XSqlQuery::XSqlQuery() : QSqlQuery()
{
}

XSqlQuery::XSqlQuery(QString q) : QSqlQuery(q)
{
	file = ""; line = 0;
	lastq = q;
}

bool XSqlQuery::exec(QString q)
{
	lastq = q;
	file = ""; line = 0;
	return QSqlQuery::exec(q);
}

bool XSqlQuery::exec()
{
	QString res;
	setForwardOnly(true);
	bool r = QSqlQuery::exec();
	if (isSelect())
		res = QString("Rows selected: %1").arg(size());
	else
		res = QString("Rows affected: %1").arg(numRowsAffected());
	qDebug() << QString("QUERY: %1 - %2").arg(query_details()).arg(res);
	return r;
}

bool XSqlQuery::prepare(QString q)
{
	lastq = q;
	setForwardOnly(true);
	return QSqlQuery::prepare(q);
}

void XSqlQuery::location(const char *f, int l)
{
	file = f + QString(f).lastIndexOf("/") +1;
	line = l;
}
