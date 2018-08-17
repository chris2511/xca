/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __DB_X509REQ_H
#define __DB_X509REQ_H

#include "db_key.h"
#include "db_x509super.h"
#include "pki_temp.h"
#include "pki_x509req.h"

class db_x509req: public db_x509super
{
	Q_OBJECT

	protected:
		dbheaderList getHeaders();
	public:
		db_x509req(MainWindow *mw);
		pki_base* insert(pki_base *item);
		pki_base *newPKI(enum pki_type type = none);
		void fillContextMenu(QMenu *menu, const QModelIndex &index);
		void store(QModelIndex index);
		void signReq(QModelIndex index);
		void toRequest(QModelIndex index);
		void load();
		QList<pki_x509req*> getAllRequests();
		void resetX509count();
		void setSigned(QModelIndex index, bool signe);

	public slots:
		void newItem(pki_temp *temp, pki_x509req *orig = NULL);
		void newItem();

	signals:
		void newCert(pki_x509req *req);
};

#endif
