/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __DB_X509_H
#define __DB_X509_H

#include <QListView>
#include <QPixmap>
#include <QTreeWidget>
#include "widgets/ExportDialog.h"
#include "db_key.h"
#include "db_x509super.h"
#include "pki_x509.h"
#include "pki_crl.h"
#include "pki_temp.h"

class db_x509: public db_x509super
{
	Q_OBJECT

	protected:
		QPixmap *certicon[4];
		pki_x509 *get1SelectedCert();
		dbheaderList getHeaders();
		void dereferenceIssuer();

	public:
		static bool treeview;
		db_x509(MainWindow *mw);
		pki_base *newPKI(enum pki_type type = none);
		pki_x509 *findIssuer(pki_x509 *client);

		bool updateView();
		void updateViewAll();
		void updateViewPKI(pki_base *pki);
		void remFromCont(const QModelIndex &idx);
		QList<pki_x509*> getAllIssuers();
		QList<pki_x509*> getCerts(bool unrevoked);
		void writeIndex(const QString &fname, bool hierarchy);
		void writeIndex(const QString &fname, QList<pki_x509*> items);
		void writeAllCerts(const QString &fname, bool unrevoked);
		pki_base *insert(pki_base *item);
		void markRequestSigned(pki_x509req *req, pki_x509 *cert);
		pki_x509 *newCert(NewX509 *dlg);
		void newCert(pki_x509 *cert);
		void writePKCS12(pki_x509 *cert, QString s, bool chain);
		void writePKCS7(pki_x509 *cert, QString s,
				exportType::etype type, QModelIndexList list);
		void fillContextMenu(QMenu *menu, const QModelIndex &index);
		void inToCont(pki_base *pki);
		void changeView();
		a1int getUniqueSerial(pki_x509 *signer);
		void toToken(QModelIndex idx, bool alwaysSelect);
		void toRequest(QModelIndex idx);
		void store(QModelIndex idx);
		void store(QModelIndexList list);
		void load();
		void caProperties(QModelIndex idx);
		void toCertificate(QModelIndex index);
		void manageRevocations(QModelIndex idx);
		void certRenewal(QModelIndexList indexes);
		void revoke(QModelIndexList indexes);
		void do_revoke(QModelIndexList indexes, const x509rev &r);
		void unRevoke(QModelIndexList indexes);

	public slots:
		void newItem();

		void newCert(pki_temp *);
		void newCert(pki_x509req *);
};

#endif
