/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2020 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DATABASE_MODEL_H
#define __DATABASE_MODEL_H

#include <QList>
#include <QObject>
#include <QStringList>
#include <QSqlDatabase>

#include "sql.h"
#include "db_base.h"
#include "lib/Passwd.h"

typedef QMap<QString, QString> DbMap;

class database_model: public QObject
{
	Q_OBJECT

	private:
		QList<db_base*> models;
		int dbTimer;
		void openSqlDB();
		QSqlError initSqlDB();
		QString dbName;
		bool checkForOldDbFormat(const QString &dbfile) const;
		enum open_result verifyOldDbPass(const QString &dbname) const;
		void importOldDatabase(const QString &dbfile);
		QString get_default_db() const;
		QString checkPre2Xdatabase() const;
		enum open_result initPass(const QString &dbName,
				const QString &passhash) const;

	public:
		database_model(const QString &dbName,
				const Passwd &pass = Passwd());
		~database_model();
		void restart_timer();
		const QString &dbname() const
		{
			return dbName;
		}
		template <class T> T *model() const
		{
			foreach(db_base *model, models) {
				T *m = dynamic_cast<T*>(model);
				if (m)
					return m;
			}
			return NULL;
		}
		void timerEvent(QTimerEvent *event);
		void dump_database(const QString &dirname) const;
		QList<db_base*> getModels() const
		{
			return models;
		}
		db_base *modelForPki(const pki_base *pki) const;
		pki_base *insert(pki_base *pki);

		static void as_default_database(const QString &db);
		static DbMap splitRemoteDbName(const QString &db);
		static bool isRemoteDB(const QString &db);
		static void openDatabase(const QString &descriptor,
					 const Passwd &pass);
		static void openRemoteDatabase(const QString &connName,
						const DbMap &params,
						const Passwd &pass);
		static void openLocalDatabase(const QString &connName,
						const QString &descriptor);
};

#endif
