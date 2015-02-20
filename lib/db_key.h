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
#include <QStringList>
#include <QObject>

class MainWindow;
class QModelIndex;
class QContextMenuEvent;

class db_key: public db_base
{
	Q_OBJECT

	protected:
		virtual dbheaderList getHeaders();
		exportType::etype clipboardFormat(QModelIndexList indexes);
	public:
		db_key(QString db, MainWindow *mw);
		QStringList getPrivateDesc();
		QStringList get0KeyDesc(bool all = false);
		pki_base *newPKI(db_header_t *head = NULL);
		void inToCont(pki_base *pki);
		void remFromCont(QModelIndex &idx);
		pki_base* insert(pki_base *item);
		void writeAll();
		void setOwnPass(QModelIndex idx, enum pki_key::passType);

	public slots:
		void newItem();
		void newItem(QString name);
		void load();
		void store(QModelIndex index);
		void showPki(pki_base *pki);

	signals:
		void delKey(pki_key *delkey);
		void newKey(pki_key *newkey);
		void keyDone(QString name);
};

#endif
