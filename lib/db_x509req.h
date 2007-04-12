/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef DB_X509REQ_H
#define DB_X509REQ_H

#include "db_key.h"
#include "db_x509super.h"
#include "pki_temp.h"
#include "pki_x509req.h"

class db_x509req: public db_x509super
{
	Q_OBJECT

	public:
		db_x509req(QString DBfile, MainWindow *mw);
		pki_base* insert(pki_base *item);
		pki_base *newPKI();
		void showContextMenu(QContextMenuEvent *e, const QModelIndex &index);

	public slots:
		void newItem(pki_temp *temp = NULL);
		void load();
		void store();
		void showPki(pki_base *pki);
		void signReq();
	signals:
		void newCert(pki_x509req *req);
};

#endif
