/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef DB_KEY_H
#define DB_KEY_H

#include "db_base.h"
#include "pki_key.h"
#include <qstringlist.h>
#include <qobject.h>

class MainWindow;
class QModelIndex;
class QContextMenuEvent;

class db_key: public db_base
{
	Q_OBJECT
	private:
		void __setOwnPass(enum pki_key::passType);
	public:
		db_key(QString db, MainWindow *mw);
		pki_base *newPKI();
		QStringList getPrivateDesc();
		QStringList get0PrivateDesc(bool all = false);
		void inToCont(pki_base *pki);
		void remFromCont(QModelIndex &idx);
		pki_base* insert(pki_base *item);
		void writeAll();
		void showContextMenu(QContextMenuEvent * e, const QModelIndex &index);

	public slots:
		void newItem();
		void load();
		void store();
		void showPki(pki_base *pki);
		void setOwnPass();
		void resetOwnPass();

	signals:
		void delKey(pki_key *delkey);
		void newKey(pki_key *newkey);
		void keyDone(QString name);
};

#endif
