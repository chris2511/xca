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
#include <QDebug>
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
		void restart_timer();
		static void openDatabase(const QString &descriptor,
					 const Passwd &pass);
		static void openRemoteDatabase(const QString &connName,
						const DbMap &params,
						const Passwd &pass);
		static void openLocalDatabase(const QString &connName,
						const QString &descriptor);
	private slots:
		void pkiChangedSlot(pki_base *pki);

	public:
		database_model(const QString &dbName,
				const Passwd &pass = Passwd());
		~database_model();
		void timerEvent(QTimerEvent *event);
		db_base *modelForPki(const pki_base *pki) const;

		QString dbname() const
		{
			return dbName;
		}
		void dump_database(const QString &dirname) const;
		QList<db_base*> getModels() const
		{
			return models;
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
		pki_base *insert(pki_base *pki);

		static DbMap splitRemoteDbName(const QString &db);
		static bool isRemoteDB(const QString &db);
		static void as_default_database(const QString &db);

	signals:
		void pkiChanged(pki_base *pki) const;
};

class xca_db
{
	private:
		database_model *db;

	public:
		xca_db() : db(nullptr) { }
		~xca_db()
		{
			close();
		}
		void open(const QString &dbName, const Passwd &pass = Passwd())
		{
			close();
			db = new database_model(dbName, pass);
			qDebug() << "Opening database:" << name();
		}
		void open_default()
		{
			open(QString());
		}
		void close()
		{
			if (db) {
				qDebug() << "Closing database:" << name();
				delete db;
				db = NULL;
			}
		}
		QString name() const
		{
			return db ? db->dbname() : QString();
		}
		bool isOpen()
		{
			return db != NULL;
		}
		template <class T> T *model() const
		{
			return db ? db->model<T>() : NULL;
		}
		void dump(const QString &dirname) const
		{
			if (db)
				db->dump_database(dirname);
		}
		void as_default() const
		{
			database_model::as_default_database(name());
		}
		QList<db_base*> getModels() const
		{
			return db ? db->getModels() : QList<db_base*>();
		}
		pki_base *insert(pki_base *pki)
		{
			return db ? db->insert(pki) : NULL;
		}
		db_base *modelForPki(const pki_base *pki) const
		{
			return db ? db->modelForPki(pki) : NULL;
		}
		void connectToDbChangeEvt(QObject *o, const char *slot)
		{
			if (db)
				QObject::connect(
					db, SIGNAL(pkiChanged(pki_base*)),
					o, slot);
		}
};

extern xca_db Database;

#endif
