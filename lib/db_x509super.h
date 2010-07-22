/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __DB_X509SUPER_H
#define __DB_X509SUPER_H

#include "db_key.h"
#include "pki_x509super.h"

class db_x509super: public db_base
{
	Q_OBJECT

	public:
		db_x509super(QString db, MainWindow *mw);
		pki_key *findKey(pki_x509super *ref);
		pki_x509super *findByByPubKey(pki_key *refkey);

	public slots:
		void delKey(pki_key *delkey);
		void newKey(pki_key *newKey);
		void toTemplate();
		void extractPubkey();
};

#endif
