/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DB_KEY_H
#define __DB_KEY_H

#include "db_base.h"
#include "pki_key.h"

class MainWindow;
class QModelIndex;
class QContextMenuEvent;

class db_key: public db_base
{
	Q_OBJECT

	protected:
		virtual dbheaderList getHeaders();
		exportType::etype clipboardFormat(QModelIndexList indexes) const;
	public:
		db_key();
		QList<pki_key*> getUnusedKeys();
		QList<pki_key*> getAllKeys();
		pki_base *newPKI(enum pki_type type = none);
		void inToCont(pki_base *pki);
		void remFromCont(const QModelIndex &idx);
		pki_base* insert(pki_base *item);
		void setOwnPass(QModelIndex idx, enum pki_key::passType);
		void loadContainer();
		pki_key *newKey(const keyjob &task, const QString &name);

	public slots:
		void load();
		void store(QModelIndex index);

	signals:
		void delKey(pki_key *delkey);
		void newKey(pki_key *newkey);
		void keyDone(pki_key *nkey);
};

#endif
