/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2010 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CERTDETAIL_H
#define __CERTDETAIL_H

#include "ui_CertDetail.h"
#include "lib/pki_x509req.h"
#include "lib/pki_x509.h"

class pki_x509;

class CertDetail: public QDialog, public Ui::CertDetail
{
		Q_OBJECT

		bool showConf;
		QVariant keySqlId, issuerSqlId, thisSqlId;
		QString conf, exts;
		QLabel *labelFromAsn1String(ASN1_STRING *s);
		pki_key *myPubKey, *tmpPubKey;
		void setCert(pki_x509 *cert);
		void setReq(pki_x509req *req);

	public:
		CertDetail(QWidget *w = nullptr);
		~CertDetail();
		void setX509super(pki_x509super *x);
		static void showCert(QWidget *parent, pki_x509super *x);

	private slots:
		void on_showExt_clicked();
		void itemChanged(pki_base *pki);
		void showPubKey();
		void showIssuer();
};

#endif
