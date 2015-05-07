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
		db_x509req(QString DBfile, MainWindow *mw);
		pki_base* insert(pki_base *item);
		pki_base *newPKI(db_header_t *head = NULL);
		void fillContextMenu(QMenu *menu, const QModelIndex &index);
		void inToCont(pki_base *pki);
		void store(QModelIndex index);
		void signReq(QModelIndex index);
		void toRequest(QModelIndex index);
		void load();
		void showPki(pki_base *pki);

	public slots:
		void newItem(pki_temp *temp, pki_x509req *orig = NULL);
		void newItem();

	signals:
		void newCert(pki_x509req *req);
};

#endif
