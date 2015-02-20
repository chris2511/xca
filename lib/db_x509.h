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

	public:
		static bool treeview;
		db_x509(QString DBfile, MainWindow *mw);
		pki_base *newPKI(db_header_t *head = NULL);
		pki_x509 *findSigner(pki_x509 *client);
		void updateAfterDbLoad();
		void updateAfterCrlLoad(pki_x509 *pki);

		bool updateView();
		void updateViewAll();
		void updateViewPKI(pki_base *pki);
		void remFromCont(QModelIndex &idx);
		QStringList getPrivateDesc();
		QStringList getSignerDesc();
		void calcEffTrust();
		QList<pki_x509*> getCerts(bool onlyTrusted);
		a1int searchSerial(pki_x509 *signer);
		void writeAllCerts(const QString fname, bool onlyTrusted);
		pki_x509 *getByIssSerial(const pki_x509 *issuer, const a1int &a);
		pki_x509 *getBySubject(const x509name &xname, pki_x509 *last = NULL);
		pki_base *insert(pki_base *item);
		void newCert(NewX509 *dlg);
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
		void showPki(pki_base *pki);
		void load();
		void caProperties(QModelIndex idx);
		void toCertificate(QModelIndex index);
		void manageRevocations(QModelIndex idx);
		void certRenewal(QModelIndexList indexes);
		void revoke(QModelIndexList indexes);
		void do_revoke(QModelIndexList indexes, const x509rev &r);
		void unRevoke(QModelIndexList indexes);
		void setTrust(QModelIndexList indexes);

	public slots:
		void newItem();

		void newCert(pki_temp *);
		void newCert(pki_x509req *);
};

#endif
