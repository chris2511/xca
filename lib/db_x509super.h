/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __DB_X509SUPER_H
#define __DB_X509SUPER_H

#include "db_key.h"
#include "pki_x509super.h"
#include <QList>
#include <QMap>

class db_x509name: public db_base
{
	Q_OBJECT

	protected:
		dbheaderList getHeaders();
	public:
		db_x509name(QString db, MainWindow *mw);
};

class db_x509super: public db_x509name
{
	Q_OBJECT

	protected:
		dbheaderList getHeaders();
	public:
		db_x509super(QString db, MainWindow *mw);
		pki_key *findKey(pki_x509super *ref);
		QList<pki_x509super *> findByPubKey(pki_key *refkey);
		void extractPubkey(QModelIndex index);
		void toTemplate(QModelIndex index);
		void toOpenssl(QModelIndex index) const;

	public slots:
		void delKey(pki_key *delkey);
		void newKey(pki_key *newKey);
};

#endif
