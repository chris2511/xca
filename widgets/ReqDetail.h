/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __REQDETAIL_H
#define __REQDETAIL_H

#include "ui_ReqDetail.h"
#include <qdialog.h>
#include <openssl/asn1.h>

class pki_x509req;

class ReqDetail: public QDialog, public Ui::ReqDetail
{
	Q_OBJECT

   public:
	ReqDetail( QWidget *parent);
	void setReq(pki_x509req *req);
	QLabel *labelFromAsn1String(ASN1_STRING *s);
};

#endif
