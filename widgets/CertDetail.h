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
		QString conf, exts;
		QLabel *labelFromAsn1String(ASN1_STRING *s);
		void setX509super(pki_x509super *x);

	public:
		CertDetail( QWidget *parent);
		void setCert(pki_x509 *cert);
		void setReq(pki_x509req *req);

	private slots:
		void on_showExt_clicked();
};

#endif
