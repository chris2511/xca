/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2017 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __SQL_H
#define __SQL_H

#include <QtSql>

#define SQL_PREPARE(q,cmd) do { \
	(q).prepare(cmd); \
	(q).location(__FILE__,__LINE__); \
} while (0)

class DbTransaction
{
	private:
		static int mutex;
		static int error;
		bool has_begun;
		void debug(const char *func, const char *file, int line);

	public:
		DbTransaction();
		~DbTransaction();
		bool begin(const char *file, int line);
		bool commit(const char *file, int line);
		bool rollback(const char *file, int line);
		bool done(QSqlError e, const char *file, int line);
};

#define Transaction DbTransaction __trans
#define TransBegin() __trans.begin(__FILE__, __LINE__)
#define TransCommit() __trans.commit(__FILE__, __LINE__)
#define TransRollback() __trans.rollback(__FILE__, __LINE__)
#define TransDone(e) __trans.done(e, __FILE__, __LINE__);

class XSqlQuery: public QSqlQuery
{
	private:
		QString lastq;
		const char *file;
		int line;
	public:
		XSqlQuery();
		XSqlQuery(QString q);

		QString query_details();
		QSqlError lastError();
		bool exec(QString q);
		bool exec();
		bool prepare(QString q);
		void location(const char *f, int l);
};

#endif
