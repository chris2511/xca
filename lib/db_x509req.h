/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __DB_X509REQ_H
#define __DB_X509REQ_H

#include "db_x509super.h"

class pki_temp;
class pki_x509req;

class db_x509req: public db_x509super
{
	Q_OBJECT

	protected:
		dbheaderList getHeaders();
	public:
		db_x509req();
		pki_base* insert(pki_base *item);
		pki_base *newPKI(enum pki_type type = none);
		void fillContextMenu(QMenu *menu, const QModelIndex &index);
		void store(QModelIndex index);
		void load();
		QList<pki_x509req*> getAllRequests();
		void resetX509count();
		void setSigned(QModelIndex index, bool signe);

	public slots:
		void newItem(pki_temp *temp, pki_x509req *orig = NULL);
		void newItem();
};

#endif
