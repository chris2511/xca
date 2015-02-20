/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __DB_CRL_H
#define __DB_CRL_H

#include "db_x509.h"
#include "pki_crl.h"
#include "widgets/ExportDialog.h"
#include <QObject>
#include <QPixmap>
#include <QContextMenuEvent>

class db_crl: public db_x509name
{
		Q_OBJECT
	protected:
		QPixmap *crlicon;
		dbheaderList getHeaders();
	public:
		db_crl(QString db, MainWindow *mw);
		pki_base *newPKI(db_header_t *head = NULL);
		void revokeCerts(pki_crl *crl);
		void inToCont(pki_base *pki);
		pki_base *insert(pki_base *item);
		void removeSigner(pki_base *signer);
		void store(QModelIndex index);
		void load();
		void showPki(pki_base *pki);
		void updateCertView();
		void updateRevocations(pki_x509 *cert);

	public slots:
		void newItem();
		void newItem(pki_x509 *cert);
};

#endif
