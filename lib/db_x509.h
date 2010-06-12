/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#ifndef __DB_X509_H
#define __DB_X509_H

#include <QtGui/QListView>
#include <QtCore/QObject>
#include <QtGui/QPixmap>
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

	public:
		static bool treeview;
		db_x509(QString DBfile, MainWindow *mw);
		pki_base *newPKI(db_header_t *head = NULL);
		pki_x509 *findSigner(pki_x509 *client);
		bool updateView();
		void updateViewAll();
		void updateViewPKI(pki_base *pki);
		void remFromCont(QModelIndex &idx);
		QStringList getPrivateDesc();
		QStringList getSignerDesc();
		void calcEffTrust();
		QList<pki_x509*> getIssuedCerts(const pki_x509 *issuer);
		QList<pki_x509*> getCerts(bool onlyTrusted);
		a1int searchSerial(pki_x509 *signer);
		void writeAllCerts(const QString fname, bool onlyTrusted);
		pki_x509 *getByIssSerial(const pki_x509 *issuer, const a1int &a);
		pki_x509 *getBySubject(const x509name &xname, pki_x509 *last = NULL);
		pki_base *insert(pki_base *item);
		void newCert(NewX509 *dlg);
		void writePKCS12(pki_x509 *cert, QString s, bool chain);
		void writePKCS7(pki_x509 *cert, QString s, int type);
		void showContextMenu(QContextMenuEvent *e, const QModelIndex &index);
		void inToCont(pki_base *pki);
		void changeView();
		a1int getUniqueSerial(pki_x509 *signer);
		void myToToken(bool alwaysSelect);

	public slots:
		void load(void);
		void newItem(void);
		void revokeCert(const x509rev &revok, const pki_x509 *issuer);
		void store();
		void showPki(pki_base *pki);
		void setMultiTrust(QAbstractItemView* view);
		void setTrust();
		void deleteFromToken();
		void extendCert();
		void revoke();
		void unRevoke();
		void genCrl();
		void caProperties();
		void toRequest();
		void toToken();
		void toOtherToken();
		void newCert(pki_temp *);
		void newCert(pki_x509req *);
		void loadPKCS12();
		void loadPKCS7();
};

#endif
