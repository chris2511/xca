/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2007 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __CRLDETAIL_H
#define __CRLDETAIL_H

#include "ui_CrlDetail.h"

class pki_crl;
class pki_base;

class CrlDetail: public QDialog, public Ui::CrlDetail
{
	Q_OBJECT

	private:
		QVariant issuerSqlId, crlSqlId;
	public:
		CrlDetail(QWidget *w = nullptr);
		void setCrl(pki_crl *crl);
		static void showCrl(QWidget *parent, pki_crl *crl);
	public slots:
		void itemChanged(pki_base *pki);
		void showIssuer();
};
#endif
