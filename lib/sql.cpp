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
#include "settings.h"
#include "widgets/XcaWarning.h"

int DbTransaction::mutex;
int DbTransaction::error;
bool DbTransaction::hasTransaction;
QList<quint64> DbTransaction::items;

quint64 DbTransaction::DatabaseStamp;

void DbTransaction::debug(const char *func, const char *file, int line)
{
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
	if (mutex > 1 || !hasTransaction)
		return true;

	QSqlDatabase db = QSqlDatabase::database();
	bool ret = db.transaction();
	if (!ret)
		XCA_SQLERROR(db.lastError());
	return ret;
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
	if (error) {
		error = 0;
		items.clear();
		return hasTransaction ? db.rollback() : true;
	}
	mutex++;
	XSqlQuery q;
	SQL_PREPARE(q, "SELECT MAX(stamp) +1 from items");
	q.exec();
	if (q.first())
		DatabaseStamp = q.value(0).toULongLong();

	SQL_PREPARE(q, "UPDATE items SET stamp=? WHERE stamp=0");
	q.bindValue(0, DatabaseStamp);
	q.exec();

	SQL_PREPARE(q, "UPDATE items SET stamp=? WHERE id=?");
	q.bindValue(0, DatabaseStamp);
	foreach(quint64 id, DbTransaction::items) {
		q.bindValue(1, id);
		q.exec();
	}
	mutex--;
	items.clear();

	bool ret = hasTransaction ? db.commit() : true;
	if (!ret)
		XCA_SQLERROR(db.lastError());
	return ret;
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

QString XSqlQuery::table_prefix;

int XSqlQuery::schemaVersion()
{
	qDebug() << "table_prefix:" << table_prefix;;
	return QSqlDatabase::database().tables()
			.contains(table_prefix + "settings") ?
				Settings["schema"] : 0;
}

QString XSqlQuery::rewriteQuery(QString _q)
{
	static const QStringList tables {
		"items" , "crls" , "private_keys" , "public_keys" ,
		"tokens" , "token_mechanism" , "templates" , "certs" ,
		"authority" , "revocations" , "requests" , "x509super" ,
		"settings" ,

		"view_public_keys" , "view_certs" , "view_requests" ,
		"view_crls" , "view_templates" , "view_private",
	};

	lastq = query = _q;
	if (table_prefix.isEmpty())
		return query;

	QString m = tables.join("|") + "|i_" + tables.join("|i_");
	m = QString("\\b(%1)").arg(m);
	query = query.replace(QRegExp(m), table_prefix + "\\1");

	return query;
}

QString XSqlQuery::query_details()
{
	QString lq = lastq;
	QList<QVariant> list = boundValues().values();
	QStringList sl;

	if (query != lastq) {
		lq = QString("%1 (PREFIX[%2]: %3)").arg(lastq)
				.arg(table_prefix).arg(query);
	}
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
	return QSqlError(QString("%1 - %2").arg(e.driverText())
					.arg(query_details()),
			 e.databaseText(), e.type(),
#if (QT_VERSION >= QT_VERSION_CHECK(5, 0, 0))
			 e.nativeErrorCode()
#else
			 e.number()
#endif
			);
}

XSqlQuery::XSqlQuery() : QSqlQuery()
{
}

XSqlQuery::XSqlQuery(QString q) : QSqlQuery()
{
	exec(q);
}

bool XSqlQuery::exec(QString q)
{
	q = rewriteQuery(q);
	file = ""; line = 0;
	return QSqlQuery::exec(q);
}

bool XSqlQuery::exec()
{
	QString res;
	setForwardOnly(true);
	bool r = QSqlQuery::exec();
	if (isSelect()) {
		res = QString("Rows selected: %1").arg(size());
	} else {
		res = QString("Rows affected: %1").arg(numRowsAffected());
		if (!DbTransaction::active()) {
			 qCritical("########## MISSING Transaction in %s(%d)",
				file, line);
		}
	}
	qDebug() << QString("QUERY: %1 - %2").arg(query_details()).arg(res);
	return r;
}

bool XSqlQuery::prepare(QString q)
{
	q = rewriteQuery(q);
	setForwardOnly(true);
	return QSqlQuery::prepare(q);
}

void XSqlQuery::location(const char *f, int l)
{
	file = f + QString(f).lastIndexOf("/") +1;
	line = l;
}
